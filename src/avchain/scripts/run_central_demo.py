"""One-command data-only demo: central active -> inactive -> active, two nodes."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
from datetime import UTC
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4

import httpx

from avchain.agent.worker import EndpointAgentWorker
from avchain.config.settings import get_settings, reset_settings_cache
from avchain.coverage.central import CheckEvent, SimulatedExternalCoverage
from avchain.database.core import init_db, reset_database_state, session_scope
from avchain.evidence.storage import EvidenceStorage
from avchain.models.orm import CentralCheckEvent
from avchain.utils.helpers import compute_sha256


async def run_demo() -> dict[str, object]:
    # Import services only after main isolated database and evidence paths.
    from avchain.ledger.service import create_app

    settings = get_settings()
    headers = {"Authorization": f"Bearer {settings.ledger_api_key}"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()),
        base_url="http://central-demo",
        trust_env=False,
    ) as client:
        ids = []
        for observable in ("a" * 64, "b" * 64):
            response = await client.post(
                "/ledger/entries", headers=headers, json={"observables": [observable]}
            )
            response.raise_for_status()
            entry_id = UUID(response.json()["id"])
            response = await client.post(
                f"/ledger/entries/{entry_id}/transitions",
                headers=headers,
                json={
                    "from_state": "suspected",
                    "to_state": "confirmed",
                    "actor": "demo-bootstrap",
                    "notes": "Synthetic catalog setup; not validator efficacy proof",
                },
            )
            response.raise_for_status()
            ids.append(entry_id)
        nodes = [
            EndpointAgentWorker(ledger_client=client, central_demo=True)
            for _ in range(2)
        ]

        async def snapshot() -> list[dict[str, bool]]:
            for node in nodes:
                await node.refresh_confirmed_entries()
            return [
                {
                    "target_active": ids[0] in node.confirmed_entries,
                    "unaffected_active": ids[1] in node.confirmed_entries,
                }
                for node in nodes
            ]

        before = await snapshot()
        feed = SimulatedExternalCoverage(client, settings.ledger_api_key)
        event_id = uuid4()
        applied = await feed.report(event_id, ids[0], covered=True)
        inactive = await snapshot()
        replay = await feed.report(event_id, ids[0], covered=True)
        after_replay = await snapshot()
        reactivation = CheckEvent(
            event_id=uuid4(),
            entry_id=ids[0],
            active=True,
            reason="Central operator reactivated the demo check",
            source="CENTRAL_REACTIVATION",
        )
        response = await client.post(
            "/ledger/checks/events",
            headers=headers,
            json=reactivation.model_dump(mode="json"),
        )
        response.raise_for_status()
        restored = await snapshot()
        # Replaying the old deactivation cannot undo the later reactivation.
        await feed.report(event_id, ids[0], covered=True)
        after_old_replay = await snapshot()
        with session_scope() as db:
            rows = (
                db.query(CentralCheckEvent).order_by(CentralCheckEvent.sequence).all()
            )
            retained_events = []
            storage = EvidenceStorage()
            for row in rows:
                raw = storage.retrieve_bytes(row.evidence_digest)
                if raw is None or compute_sha256(raw) != row.evidence_digest:
                    raise ValueError("Cannot retain corrupt demo event evidence")
                retained_events.append(
                    {
                        "event_id": row.event_id,
                        "entry_id": row.entry_id,
                        "active": row.active,
                        "reason": row.reason,
                        "timestamp": row.timestamp.replace(tzinfo=UTC).isoformat(),
                        "evidence_digest": row.evidence_digest,
                        "evidence": json.loads(raw),
                    }
                )
            events = len(retained_events)
        passed = (
            all(x["target_active"] and x["unaffected_active"] for x in before)
            and all(not x["target_active"] and x["unaffected_active"] for x in inactive)
            and inactive == after_replay
            and before == restored == after_old_replay
            and replay["replayed"] is True
            and events == 2
        )
        return {
            "status": "PASS" if passed else "FAIL",
            "coverage_source": "SIMULATED",
            "real_vendor_integration": False,
            "local_antivirus_required": False,
            "claim": (
                "Two logical nodes synchronize central supplemental-check state; "
                "no malware efficacy claim"
            ),
            "baseline": before,
            "covered": inactive,
            "replay": after_replay,
            "reactivated": restored,
            "old_event_replay": after_old_replay,
            "events_stored": events,
            "events": retained_events,
            "target_entry_id": str(ids[0]),
            "unaffected_entry_id": str(ids[1]),
            "coverage_evidence_digest": applied["evidence_digest"],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="avchain-central-demo-") as temporary:
        root = Path(temporary)
        with patch.dict(
            os.environ,
            {
                "DATABASE_URL": f"sqlite:///{root / 'ledger.db'}",
                "EVIDENCE_DIR": str(root / "evidence"),
                "LLM_PROVIDER": "disabled",
                "ENDPOINT_SCAN_ENABLED": "false",
                "ENDPOINT_SIGNING_ENABLED": "false",
            },
        ):
            reset_settings_cache()
            init_db()
            try:
                report = asyncio.run(run_demo())
            finally:
                reset_database_state()
                reset_settings_cache()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(report["status"])
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
