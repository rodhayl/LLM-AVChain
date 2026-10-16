from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from avchain.consensus.registry import ValidatorRegistry
from avchain.crypto.keys import canonicalize, load_public_key, verify_signature
from avchain.evidence.storage import EvidenceStorage, store_evidence_item
from avchain.incident.models import (
    RemediationPackage,
    SignedPackage,
    SignedRevocation,
    ValidatorApproval,
)
from avchain.models.orm import (
    Entry,
    EntryEvidenceLink,
    RemediationPackageORM,
    RemediationRevocationORM,
)
from avchain.utils.helpers import compute_sha256


def package_digest(package: RemediationPackage) -> str:
    return compute_sha256(canonicalize(package.model_dump(mode="json")))


def verify_approvals(
    payload: dict[str, object],
    approvals: list[ValidatorApproval],
    registry: ValidatorRegistry,
    *,
    domain: str,
) -> None:
    # Domain separation prevents lifecycle votes or revocations being reused.
    signed = canonicalize({"domain": domain, "payload": payload})
    voters: set[str] = set()
    keys: set[bytes] = set()
    for approval in approvals:
        record = registry.get(approval.validator_id)
        if record is None or approval.validator_id in voters:
            raise ValueError("Unknown or duplicate validator")
        key = load_public_key(record.public_key)
        fingerprint = key.public_bytes_raw()
        if fingerprint in keys or not verify_signature(key, signed, approval.signature):
            raise ValueError("Invalid or reused signing key")
        voters.add(approval.validator_id)
        keys.add(fingerprint)
    if registry.count == 0 or len(voters) < registry.majority_threshold():
        raise ValueError("Package lacks independent validator majority")


def verify_package(
    envelope: SignedPackage, registry: ValidatorRegistry, *, now: datetime | None = None
) -> None:
    package = envelope.package
    current = now or datetime.now(UTC)
    if not package.issued_at <= current < package.expires_at:
        raise ValueError("Package not currently valid")
    verify_approvals(
        package.model_dump(mode="json"),
        envelope.approvals,
        registry,
        domain="avchain-remediation-package-v1",
    )


class KnowledgeStore:
    """Shares the existing ledger database, evidence store and validator trust.

    Publication is a separate majority-signed gate. The ledger API key alone
    cannot authorize a remediation package or its revocation.
    """

    def __init__(
        self, db: Session, storage: EvidenceStorage, registry: ValidatorRegistry
    ):
        self.db, self.storage, self.registry = db, storage, registry

    def publish(self, envelope: SignedPackage) -> SignedPackage:
        verify_package(envelope, self.registry)
        p = envelope.package
        entry = self.db.get(Entry, str(p.entry_id))
        if entry is None or entry.state != "confirmed":
            raise ValueError("Publication requires a confirmed ledger entry")
        for digest in p.evidence_digests:
            linked = self.db.get(
                EntryEvidenceLink, {"entry_id": str(p.entry_id), "digest": digest}
            )
            raw = self.storage.retrieve_bytes(digest)
            if linked is None or raw is None or compute_sha256(raw) != digest:
                raise ValueError("Missing, unrelated or tampered source evidence")
        latest = (
            self.db.query(RemediationPackageORM)
            .filter_by(package_id=p.package_id)
            .order_by(RemediationPackageORM.version.desc())
            .first()
        )
        if latest is not None and p.version != latest.version + 1:
            raise ValueError("Package version must advance exactly once")
        if latest is None and p.version != 1:
            raise ValueError("First package version must be 1")
        raw = canonicalize(envelope.model_dump(mode="json"))
        store_evidence_item(
            self.db, self.storage, str(p.entry_id), raw, "application/json"
        )
        self.db.add(
            RemediationPackageORM(
                package_id=p.package_id,
                version=p.version,
                entry_id=str(p.entry_id),
                digest=package_digest(p),
                envelope_json=raw.decode(),
            )
        )
        self.db.commit()
        return envelope

    def latest(self, package_id: str, *, minimum_version: int = 1) -> SignedPackage:
        row = (
            self.db.query(RemediationPackageORM)
            .filter_by(package_id=package_id)
            .order_by(RemediationPackageORM.version.desc())
            .first()
        )
        if row is None or row.version < minimum_version:
            raise ValueError("Unknown package or version rollback")
        if self.db.get(
            RemediationRevocationORM, {"package_id": package_id, "version": row.version}
        ):
            raise ValueError("Package revoked")
        entry = self.db.get(Entry, row.entry_id)
        if entry is None or entry.state != "confirmed":
            raise ValueError("Package source entry no longer confirmed")
        envelope = SignedPackage.model_validate_json(row.envelope_json)
        verify_package(envelope, self.registry)
        if (
            package_digest(envelope.package) != row.digest
            or envelope.package.package_id != row.package_id
            or envelope.package.version != row.version
            or str(envelope.package.entry_id) != row.entry_id
        ):
            raise ValueError("Stored package integrity failure")
        for digest in envelope.package.evidence_digests:
            linked = self.db.get(
                EntryEvidenceLink, {"entry_id": row.entry_id, "digest": digest}
            )
            raw = self.storage.retrieve_bytes(digest)
            if linked is None or raw is None or compute_sha256(raw) != digest:
                raise ValueError("Package source evidence integrity failure")
        return envelope

    def revoke(self, envelope: SignedRevocation) -> None:
        r = envelope.revocation
        if r.timestamp.tzinfo is None or abs(
            datetime.now(UTC) - r.timestamp
        ) > timedelta(minutes=5):
            raise ValueError("Revocation timestamp must be current and timezone-aware")
        verify_approvals(
            r.model_dump(mode="json"),
            envelope.approvals,
            self.registry,
            domain="avchain-remediation-revocation-v1",
        )
        row = self.db.get(
            RemediationPackageORM, {"package_id": r.package_id, "version": r.version}
        )
        if row is None or row.digest != r.package_digest:
            raise ValueError("Revocation must identify an existing exact package")
        key = {"package_id": r.package_id, "version": r.version}
        if self.db.get(RemediationRevocationORM, key) is not None:
            raise ValueError("Package already revoked")
        self.db.add(
            RemediationRevocationORM(**key, envelope_json=envelope.model_dump_json())
        )
        self.db.commit()
