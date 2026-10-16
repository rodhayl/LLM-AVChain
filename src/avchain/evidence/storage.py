from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from avchain.config.settings import get_settings
from avchain.models.orm import EntryEvidenceLink, EvidenceObject
from avchain.models.schemas import EvidenceItem
from avchain.utils.helpers import compute_sha256, ensure_directory


class EvidenceStorage:
    def __init__(self, evidence_dir: str | Path | None = None) -> None:
        configured_dir = evidence_dir or get_settings().evidence_dir
        self.evidence_dir = ensure_directory(configured_dir)

    def store_bytes(self, data: bytes) -> tuple[str, int]:
        digest = compute_sha256(data)
        self._path_for(digest).write_bytes(data)
        return digest, len(data)

    def retrieve_bytes(self, digest: str) -> bytes | None:
        evidence_path = self._path_for(digest)
        if not evidence_path.exists():
            return None
        return evidence_path.read_bytes()

    def exists(self, digest: str) -> bool:
        return self._path_for(digest).exists()

    def _path_for(self, digest: str) -> Path:
        return self.evidence_dir / digest


def encode_evidence_payload(data: Any, content_type: str) -> bytes:
    if isinstance(data, bytes):
        return data
    if content_type == "application/json":
        from avchain.utils.helpers import canonical_json_bytes

        return canonical_json_bytes(data)
    return str(data).encode("utf-8")


def store_evidence_item(
    db: Session,
    storage: EvidenceStorage,
    entry_id: str,
    data: bytes,
    content_type: str,
    purpose: str = "supporting",
) -> EvidenceItem:
    digest, size = storage.store_bytes(data)
    evidence_item = db.get(EvidenceObject, digest)
    if evidence_item is None:
        evidence_item = EvidenceObject(
            digest=digest,
            entry_id=entry_id,
            purpose=purpose,
            content_type=content_type,
            size=size,
        )
        db.add(evidence_item)

    link = db.get(EntryEvidenceLink, {"entry_id": entry_id, "digest": digest})
    if link is None:
        db.add(EntryEvidenceLink(entry_id=entry_id, digest=digest))

    db.flush()
    return EvidenceItem(
        digest=digest,
        entry_id=UUID(entry_id),
        content_type=evidence_item.content_type,
        size=evidence_item.size,
        created_at=evidence_item.created_at,
    )


def get_evidence_item(db: Session, digest: str) -> EvidenceObject | None:
    return db.get(EvidenceObject, digest)


def list_evidence_items(db: Session, entry_id: str) -> list[EvidenceItem]:
    rows = (
        db.query(EntryEvidenceLink, EvidenceObject)
        .join(EvidenceObject, EntryEvidenceLink.digest == EvidenceObject.digest)
        .filter(EntryEvidenceLink.entry_id == entry_id)
        .order_by(EvidenceObject.created_at.asc())
        .all()
    )
    return [
        EvidenceItem(
            digest=evidence.digest,
            entry_id=UUID(link.entry_id),
            content_type=evidence.content_type,
            size=evidence.size,
            created_at=evidence.created_at,
        )
        for link, evidence in rows
    ]
