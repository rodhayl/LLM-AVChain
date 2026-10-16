"""Historical real-LLM evidence + fresh SIMULATED central-catalog continuation.

Research-only command. No model, remediation, live publication or native node runs.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import UUID, uuid5

import httpx
from sqlalchemy.orm import Session

from avchain.agent.worker import EndpointAgentWorker
from avchain.config.settings import get_settings, reset_settings_cache
from avchain.coverage.central import CheckEvent, SimulatedExternalCoverage
from avchain.crypto.keys import canonicalize, load_public_key, verify_signature
from avchain.database.core import create_engine_from_url, get_session
from avchain.evidence.storage import EvidenceStorage
from avchain.incident.knowledge import package_digest
from avchain.incident.models import SignedPackage
from avchain.models.orm import Base, CentralCheckEvent, Entry, EntryEvent
from avchain.models.schemas import ThreatEntry
from avchain.utils.helpers import compute_sha256

HISTORICAL_SOURCE_SHA = "0a05947e97aae5e8035ab47bbe20fdec845ab06b"
EVIDENCE_COMMIT = "f80ec63faa1ecf2f01aaf3f83eb5427032da68e8"
EVIDENCE_PATH = "reports/incident_response_local_permission_v4"
ENTRY_ID = UUID("14dcc46f-6453-4897-b536-b3c86eea4a58")
PACKAGE_DIGEST = "3b46b9290de8ec2939a5d22dd386cea512e7dea7b24adb7ffadd736f3b619cd7"
ORIGINAL_ARCHIVE_SHA256 = {
    "REPORT.md": "040838bb4dbd3bc3db55b944aa2039a1d8e5c0ab666694681c4bf1ad9fca00e8",
    "incident-llm.json": (
        "39fec993a58aeaac6ca53501e1b910df20552b861111ce186d7707d5839d8a58"
    ),
    "verification.json": (
        "6635ad5dd6f6177e07ac22fb0f9c779da83b0338d89e9d39a24eaf88e1690947"
    ),
}

# Only REPORT.md is a privacy-preserving derivative. Signed incident evidence
# and verification retain their exact original bytes and hashes.
ARCHIVE_SHA256 = {
    **ORIGINAL_ARCHIVE_SHA256,
    "REPORT.md": "98ed395c4078a08c51de7010d4fda9255d64d27ffe4658b16490884548b28767",
}


def verify_history(directory: Path) -> dict[str, Any]:
    """Validate the pinned public evidence set, never grant execution authority.

    The report is a declared privacy-preserving derivative; the signed incident
    and verification files retain their original bytes. These public keys are not
    installed as a live validator registry. No clock override or renewal occurs.
    """
    raw = {}
    for name, digest in ARCHIVE_SHA256.items():
        raw[name] = (directory / name).read_bytes()
        if compute_sha256(raw[name]) != digest:
            raise ValueError(f"Historical archive hash mismatch: {name}")
    incident: dict[str, Any] = json.loads(raw["incident-llm.json"])
    verification = json.loads(raw["verification.json"])
    envelope = SignedPackage.model_validate(incident["package"])
    package = envelope.package
    entry = ThreatEntry.model_validate(incident["ledger_final"])
    if (
        package.entry_id != ENTRY_ID
        or entry.id != ENTRY_ID
        or package_digest(package) != PACKAGE_DIGEST
        or incident["package_digest"] != PACKAGE_DIGEST
        or verification["package_digest"] != PACKAGE_DIGEST
    ):
        raise ValueError("Historical entry/package identity mismatch")
    signed = canonicalize(
        {
            "domain": "avchain-remediation-package-v1",
            "payload": package.model_dump(mode="json"),
        }
    )
    keys: set[bytes] = set()
    validators: set[str] = set()
    for approval in envelope.approvals:
        key = load_public_key(incident["validator_public_keys"][approval.validator_id])
        if (
            key.public_bytes_raw() in keys
            or approval.validator_id in validators
            or not verify_signature(key, signed, approval.signature)
        ):
            raise ValueError("Invalid historical package signature")
        keys.add(key.public_bytes_raw())
        validators.add(approval.validator_id)
    if validators != {"validator1", "validator2"}:
        raise ValueError("Expected two distinct archived package signatures")
    # The archived report records the original run ending at this UTC time.
    historical_run_end = datetime(2026, 10, 11, 14, 58, 52, 697000, tzinfo=UTC)
    if not package.issued_at <= historical_run_end < package.expires_at:
        raise ValueError("Package was not valid during the archived run")
    source_case_digest = compute_sha256(canonicalize(incident["source_case"]))
    if (
        source_case_digest != verification["source_case_digest"]
        or source_case_digest not in package.evidence_digests
        or incident["source_case"]["incident_digest"]
        != verification["source_incident_digest"]
        or verification["source_incident_digest"] not in package.evidence_digests
        or incident["source_case"]["knowledge"] != incident["source_knowledge"]
        or compute_sha256(canonicalize(incident["source_knowledge"]))
        != incident["source_knowledge_digest"]
    ):
        raise ValueError("Historical signed source links disagree")
    if (
        HISTORICAL_SOURCE_SHA not in raw["REPORT.md"].decode("utf-8")
        or incident["status"] != "passed"
        or incident["mode"] != "local_llm"
        or incident["real_model_executed"] is not True
        or incident["source_analysis"]["prompt_version"] != "incident-v4"
        or verification["result"] != "PASS"
        or verification["validated_real_outputs"] != 4
        or verification["failed_checks"]
        or verification["NOT_RUN"]
        or entry.state.value != "confirmed"
    ):
        raise ValueError("Historical report does not describe the expected v4 PASS")
    return incident


def _import_historical_snapshot(db: Session, entry: ThreatEntry) -> None:
    """Demo-only import into our new empty DB, not a production import endpoint.

    Copy identity, observables and lifecycle history only. Missing original
    evidence bytes are not fabricated or installed, nor is a runnable package.
    """
    if db.query(Entry).count():
        raise ValueError("Research import requires an empty temporary ledger")
    db.add(
        Entry(
            id=str(entry.id),
            observables_json=json.dumps(entry.observables),
            state=entry.state.value,
            attack_techniques_json=(
                json.dumps(entry.attack_techniques) if entry.attack_techniques else None
            ),
            tlp_label=entry.tlp_label,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
        )
    )
    db.flush()
    for event in entry.history:
        db.add(
            EntryEvent(
                entry_id=str(entry.id),
                timestamp=event.timestamp,
                from_state=event.from_state.value if event.from_state else None,
                to_state=event.to_state.value,
                actor=event.actor,
                proposal_ids_json=json.dumps(event.proposal_ids),
                notes=event.notes,
            )
        )
    db.commit()


async def _continue_catalog(incident: dict[str, Any], root: Path) -> dict[str, Any]:
    from avchain.ledger.service import create_app

    entry = ThreatEntry.model_validate(incident["ledger_final"])
    engine = create_engine_from_url(f"sqlite:///{root / 'ledger.db'}")
    Base.metadata.create_all(engine)
    storage = EvidenceStorage(root / "evidence")

    def temporary_session() -> Iterator[Session]:
        with Session(engine) as db:
            yield db

    try:
        with Session(engine) as db:
            _import_historical_snapshot(db, entry)
        app = create_app(storage=storage)
        app.dependency_overrides[get_session] = temporary_session
        settings = get_settings()
        headers = {"Authorization": f"Bearer {settings.ledger_api_key}"}
        # ASGITransport stays in process and does not start service lifespans.
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://research-continuation",
            trust_env=False,
        ) as client:
            response = await client.post(
                "/ledger/entries", headers=headers, json={"observables": ["a" * 64]}
            )
            response.raise_for_status()
            unaffected_id = UUID(response.json()["id"])
            response = await client.post(
                f"/ledger/entries/{unaffected_id}/transitions",
                headers=headers,
                json={
                    "from_state": "suspected",
                    "to_state": "confirmed",
                    "actor": "research-control-bootstrap",
                    "notes": "Unrelated synthetic control; not new consensus evidence",
                },
            )
            response.raise_for_status()
            unaffected_before = response.json()
            nodes = [
                EndpointAgentWorker(ledger_client=client, central_demo=True)
                for _ in range(2)
            ]

            async def snapshot() -> list[dict[str, Any]]:
                result = []
                for node in nodes:
                    await node.refresh_confirmed_entries()
                    if node.central_sync_error:
                        raise ValueError("Research catalog synchronization failed")
                    result.append(
                        {
                            "target_active": ENTRY_ID in node.confirmed_entries,
                            "target_observables": sorted(
                                node.confirmed_entries.get(ENTRY_ID, frozenset())
                            ),
                            "unaffected_active": unaffected_id
                            in node.confirmed_entries,
                            "unaffected_observables": sorted(
                                node.confirmed_entries.get(unaffected_id, frozenset())
                            ),
                        }
                    )
                return result

            baseline = await snapshot()
            feed = SimulatedExternalCoverage(client, settings.ledger_api_key)
            covered_id = uuid5(ENTRY_ID, "research-simulated-coverage")
            applied = await feed.report(covered_id, ENTRY_ID, covered=True)
            covered = await snapshot()
            replay = await feed.report(covered_id, ENTRY_ID, covered=True)
            after_replay = await snapshot()
            event = CheckEvent(
                event_id=uuid5(ENTRY_ID, "research-central-reactivation"),
                entry_id=ENTRY_ID,
                active=True,
                reason="Research continuation: central supplemental-check reactivation",
                source="CENTRAL_REACTIVATION",
            )
            response = await client.post(
                "/ledger/checks/events",
                headers=headers,
                json=event.model_dump(mode="json"),
            )
            response.raise_for_status()
            reactivated = await snapshot()
            stale_replay = await feed.report(covered_id, ENTRY_ID, covered=True)
            after_stale_replay = await snapshot()
            response = await client.get(f"/ledger/entries/{ENTRY_ID}", headers=headers)
            response.raise_for_status()
            final_entry = response.json()
            response = await client.get(
                f"/ledger/entries/{unaffected_id}", headers=headers
            )
            response.raise_for_status()
            unaffected_unchanged = response.json() == unaffected_before
        with Session(engine) as db:
            rows = (
                db.query(CentralCheckEvent).order_by(CentralCheckEvent.sequence).all()
            )
            events = []
            for row in rows:
                raw = storage.retrieve_bytes(row.evidence_digest)
                if raw is None or compute_sha256(raw) != row.evidence_digest:
                    raise ValueError("Cannot retain corrupt central-event evidence")
                events.append(
                    {
                        "sequence": row.sequence,
                        "timestamp": row.timestamp.replace(tzinfo=UTC).isoformat(),
                        "evidence_digest": row.evidence_digest,
                        "evidence": json.loads(raw),
                    }
                )
        historical_fields = set(incident["ledger_final"]) - {"evidence_digests"}
        identity_unchanged = all(
            final_entry[key] == incident["ledger_final"][key]
            for key in historical_fields
        )
        checks = {
            "same_entry_observables_history": identity_unchanged,
            "both_nodes_start_active": all(
                node["target_active"]
                and node["target_observables"] == sorted(entry.observables)
                for node in baseline
            ),
            "both_nodes_become_inactive": all(
                not node["target_active"] and node["target_observables"] == []
                for node in covered
            ),
            "unrelated_entry_unchanged": unaffected_unchanged
            and all(
                node["unaffected_active"]
                and node["unaffected_observables"] == ["a" * 64]
                for state in (
                    baseline,
                    covered,
                    after_replay,
                    reactivated,
                    after_stale_replay,
                )
                for node in state
            ),
            "duplicate_idempotent": replay["replayed"] is True
            and covered == after_replay,
            "reactivated_on_both_nodes": baseline == reactivated,
            "stale_replay_cannot_reverse": stale_replay["replayed"] is True
            and baseline == after_stale_replay,
            "exactly_two_new_events": len(events) == 2,
            "first_event_was_new": applied["replayed"] is False,
        }
        return {
            "status": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks,
            "target_entry_id": str(ENTRY_ID),
            "package_digest": PACKAGE_DIGEST,
            "unaffected_entry_id": str(unaffected_id),
            "baseline": baseline,
            "covered": covered,
            "replay": after_replay,
            "reactivated": reactivated,
            "old_event_replay": after_stale_replay,
            "events_stored": len(events),
            "events": events,
            "historical_ledger_snapshot": incident["ledger_final"],
        }
    finally:
        engine.dispose()


async def run_demo(evidence_dir: Path) -> dict[str, Any]:
    incident = verify_history(evidence_dir)
    with tempfile.TemporaryDirectory(
        prefix="avchain-research-continuation-"
    ) as temporary:
        root = Path(temporary)
        with patch.dict(
            os.environ,
            {
                "DATABASE_URL": f"sqlite:///{root / 'ledger.db'}",
                "EVIDENCE_DIR": str(root / "evidence"),
                "LLM_PROVIDER": "disabled",
                "ENDPOINT_SCAN_ENABLED": "false",
                "ENDPOINT_NATIVE_SNAPSHOT_ENABLED": "false",
                "ENDPOINT_SIGNING_ENABLED": "false",
            },
        ):
            reset_settings_cache()
            try:
                result = await _continue_catalog(incident, root)
            finally:
                reset_settings_cache()
    return {
        **result,
        "claim": (
            "Historical real v4 LLM + fresh SIMULATED central-catalog continuation"
        ),
        "fresh_live_end_to_end": False,
        "coverage_source": "SIMULATED",
        "real_vendor_integration": False,
        "logical_nodes": 2,
        "fresh_model_calls": 0,
        "fresh_remediation_executions": 0,
        "package_execution_authorized": False,
        "historical_import_simulation": True,
        "fresh_continuation_at": datetime.now(UTC).isoformat(),
        "historical_source_sha": HISTORICAL_SOURCE_SHA,
        # Original history is retained privately; do not advertise a stale URL.
        "historical_evidence_url": None,
        "historical_evidence_commit": EVIDENCE_COMMIT,
        "historical_file_sha256": ORIGINAL_ARCHIVE_SHA256,
        "public_evidence_file_sha256": ARCHIVE_SHA256,
        "report_sanitization": {
            "kind": "privacy-preserving-public-derivative",
            "original_report_sha256": ORIGINAL_ARCHIVE_SHA256["REPORT.md"],
            "public_report_sha256": ARCHIVE_SHA256["REPORT.md"],
            "signed_incident_bytes_unchanged": True,
            "verification_bytes_unchanged": True,
            "path_aliases_are_synthetic": True,
        },
        "historical_signatures_verified": 2,
        "historical_package_expires_at": incident["package"]["package"]["expires_at"],
        "historical_package_expired_at_run": datetime.now(UTC)
        >= SignedPackage.model_validate(incident["package"]).package.expires_at,
        "limitations": [
            "Imported historical identity/observables/lifecycle only; no new consensus",
            "Original evidence references retained in report; "
            "absent bytes not imported",
            "Public report uses synthetic dependency-path aliases; "
            "original input/environment cannot be reconstructed from them",
            "Archival signatures and past validity confer "
            "no current execution authority",
            "Catalog distribution to logical workers only; "
            "no package redistribution or endpoint execution",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() in {
        (args.evidence_dir / name).resolve() for name in ARCHIVE_SHA256
    }:
        parser.exit(
            2, "Research continuation blocked: cannot overwrite historical evidence\n"
        )
    try:
        report = asyncio.run(run_demo(args.evidence_dir))
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(2, f"Research continuation blocked: {exc}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(report["status"])
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
