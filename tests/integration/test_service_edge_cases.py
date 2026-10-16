from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from avchain.consensus.service import create_app as create_consensus_app
from avchain.coverage.service import create_app as create_coverage_app
from avchain.crypto.keys import canonicalize, load_private_key, sign_message
from avchain.ledger.service import create_app as create_ledger_app
from avchain.utils.helpers import derive_proposal_id


class FailingLedgerGateway:
    async def transition_entry(self, entry_id: str, transition) -> dict[str, str]:
        _ = entry_id, transition
        raise httpx.ConnectError("ledger unavailable")


class FailingConsensusGateway:
    async def request_review(self, entry_id: str, reason: str) -> dict[str, str]:
        _ = entry_id, reason
        raise httpx.ConnectError("consensus unavailable")


async def _create_entry(ledger_client, auth_headers, entry_payload) -> dict:
    response = await ledger_client.post(
        "/ledger/entries",
        json=entry_payload,
        headers=auth_headers("ledger"),
    )
    assert response.status_code == 201
    return response.json()


@pytest.mark.asyncio
async def test_ledger_validation_and_error_paths(
    ledger_client,
    auth_headers,
    entry_payload,
) -> None:
    invalid_state_response = await ledger_client.get(
        "/ledger/entries",
        params={"state": "invalid"},
        headers=auth_headers("ledger"),
    )
    assert invalid_state_response.status_code == 400

    entry = await _create_entry(ledger_client, auth_headers, entry_payload)

    mismatch_response = await ledger_client.post(
        f"/ledger/entries/{entry['id']}/transitions",
        json={
            "from_state": "confirmed",
            "to_state": "review",
            "actor": "consensus",
            "proposal_ids": [],
            "notes": "bad transition",
        },
        headers=auth_headers("ledger"),
    )
    assert mismatch_response.status_code == 400

    missing_response = await ledger_client.post(
        "/ledger/entries/00000000-0000-0000-0000-000000000000/transitions",
        json={
            "from_state": "suspected",
            "to_state": "review",
            "actor": "timeout",
            "proposal_ids": [],
            "notes": None,
        },
        headers=auth_headers("ledger"),
    )
    assert missing_response.status_code == 404

    missing_entry_response = await ledger_client.get(
        "/ledger/entries/00000000-0000-0000-0000-000000000000",
        headers=auth_headers("ledger"),
    )
    assert missing_entry_response.status_code == 404

    missing_feedback_response = await ledger_client.post(
        "/ledger/entries/00000000-0000-0000-0000-000000000000/feedback",
        json={"digest": "deadbeef"},
        headers=auth_headers("ledger"),
    )
    assert missing_feedback_response.status_code == 404

    bad_feedback_response = await ledger_client.post(
        f"/ledger/entries/{entry['id']}/feedback",
        json={"digest": "deadbeef"},
        headers=auth_headers("ledger"),
    )
    assert bad_feedback_response.status_code == 400


@pytest.mark.asyncio
async def test_evidence_json_and_missing_file_paths(
    ledger_client,
    evidence_client,
    auth_headers,
    entry_payload,
    storage,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)

    add_response = await evidence_client.post(
        "/evidence",
        json={"entry_id": entry["id"], "data": {"kind": "note"}},
        headers={**auth_headers("evidence"), "Content-Type": "application/json"},
    )
    assert add_response.status_code == 201
    assert set(add_response.json()) == {"digest", "size", "content_type"}
    digest = add_response.json()["digest"]

    multipart_success_response = await evidence_client.post(
        "/evidence",
        headers=auth_headers("evidence"),
        data={"entry_id": entry["id"]},
        files={"file": ("note.txt", b"multipart-note", "text/plain")},
    )
    assert multipart_success_response.status_code == 201
    assert multipart_success_response.json()["content_type"] == "text/plain"

    multipart_missing_response = await evidence_client.post(
        "/evidence",
        headers=auth_headers("evidence"),
        files={},
        data={"entry_id": entry["id"]},
    )
    assert multipart_missing_response.status_code == 400

    multipart_missing_entry_id_response = await evidence_client.post(
        "/evidence",
        headers=auth_headers("evidence"),
        files={"file": ("note.txt", b"missing-entry-id", "text/plain")},
    )
    assert multipart_missing_entry_id_response.status_code == 400

    missing_entry_id_response = await evidence_client.post(
        "/evidence",
        json={"data": {"kind": "note"}},
        headers={**auth_headers("evidence"), "Content-Type": "application/json"},
    )
    assert missing_entry_id_response.status_code == 400

    loose_json_response = await evidence_client.post(
        "/evidence",
        json={"entry_id": entry["id"], "kind": "note"},
        headers={**auth_headers("evidence"), "Content-Type": "application/json"},
    )
    assert loose_json_response.status_code == 400

    extra_field_response = await evidence_client.post(
        "/evidence",
        json={"entry_id": entry["id"], "data": {"kind": "note"}, "unexpected": True},
        headers={**auth_headers("evidence"), "Content-Type": "application/json"},
    )
    assert extra_field_response.status_code == 400

    unknown_entry_response = await evidence_client.post(
        "/evidence",
        json={"entry_id": "00000000-0000-0000-0000-000000000000", "data": {"a": 1}},
        headers={**auth_headers("evidence"), "Content-Type": "application/json"},
    )
    assert unknown_entry_response.status_code == 404

    evidence_path = storage._path_for(digest)
    evidence_path.unlink()
    missing_file_response = await evidence_client.get(
        f"/evidence/{digest}",
        headers=auth_headers("evidence"),
    )
    assert missing_file_response.status_code == 404

    unknown_list_response = await evidence_client.get(
        "/evidence/entries/00000000-0000-0000-0000-000000000000",
        headers=auth_headers("evidence"),
    )
    assert unknown_list_response.status_code == 404


@pytest.mark.asyncio
async def test_consensus_and_coverage_edge_cases(
    ledger_client,
    consensus_client,
    coverage_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)

    unknown_validator_response = await consensus_client.post(
        "/consensus/proposals",
        json={
            "proposal_id": "proposal-x",
            "entry_id": entry["id"],
            "validator_id": "unknown-validator",
            "action": "promote",
            "confidence": 0.9,
            "explanation": "bad actor",
            "timestamp": entry["updated_at"],
            "signature": "bad",
        },
        headers=auth_headers("consensus"),
    )
    assert unknown_validator_response.status_code == 400

    invalid_signature_response = await consensus_client.post(
        "/consensus/proposals",
        json={
            "proposal_id": "proposal-invalid-sig",
            "entry_id": entry["id"],
            "validator_id": "validator1",
            "action": "promote",
            "confidence": 0.9,
            "explanation": "bad signature",
            "timestamp": entry["updated_at"],
            "signature": "bad-signature",
        },
        headers=auth_headers("consensus"),
    )
    assert invalid_signature_response.status_code == 400

    private_key = load_private_key(
        Path(validator_key_paths["validator1"]).read_text(encoding="utf-8")
    )
    missing_entry_payload = {
        "entry_id": str(uuid4()),
        "validator_id": "validator1",
        "action": "promote",
        "confidence": 0.9,
        "explanation": "signed but missing",
        "timestamp": entry["updated_at"],
    }
    missing_entry_payload["proposal_id"] = derive_proposal_id(
        entry_id=missing_entry_payload["entry_id"],
        validator_id=missing_entry_payload["validator_id"],
        timestamp=datetime.fromisoformat(entry["updated_at"].replace("Z", "+00:00")),
    )
    missing_entry_signature = sign_message(
        private_key,
        canonicalize(missing_entry_payload),
    )
    missing_entry_proposal_response = await consensus_client.post(
        "/consensus/proposals",
        json={**missing_entry_payload, "signature": missing_entry_signature},
        headers=auth_headers("consensus"),
    )
    assert missing_entry_proposal_response.status_code == 404

    ignored_review_response = await consensus_client.post(
        "/consensus/review_requests",
        json={"entry_id": entry["id"], "reason": "coverage_threshold_exceeded"},
        headers=auth_headers("consensus"),
    )
    assert ignored_review_response.status_code == 200
    assert ignored_review_response.json()["status"] == "ignored"

    missing_review_response = await consensus_client.post(
        "/consensus/review_requests",
        json={
            "entry_id": "00000000-0000-0000-0000-000000000000",
            "reason": "coverage_threshold_exceeded",
        },
        headers=auth_headers("consensus"),
    )
    assert missing_review_response.status_code == 404

    missing_metric_response = await coverage_client.get(
        "/coverage/metrics/00000000-0000-0000-0000-000000000000",
        headers=auth_headers("coverage"),
    )
    assert missing_metric_response.status_code == 404

    metric_response = await coverage_client.get(
        f"/coverage/metrics/{entry['id']}",
        headers=auth_headers("coverage"),
    )
    assert metric_response.status_code == 200
    assert metric_response.json()["vendors_total"] == 0

    missing_coverage_response = await coverage_client.post(
        "/coverage/reports",
        json={
            "entry_id": "00000000-0000-0000-0000-000000000000",
            "vendor": "VendorX",
            "detected": True,
            "timestamp": "2026-04-09T00:00:00Z",
        },
        headers=auth_headers("coverage"),
    )
    assert missing_coverage_response.status_code == 404


@pytest.mark.asyncio
async def test_consensus_and_coverage_gateway_failures_return_502(
    test_environment: dict[str, str],
    auth_headers,
    storage,
) -> None:
    _ = test_environment
    failing_consensus_app = create_consensus_app(ledger_gateway=FailingLedgerGateway())
    failing_coverage_app = create_coverage_app(
        consensus_gateway=FailingConsensusGateway()
    )

    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=failing_consensus_app),
            base_url="http://consensus",
        ) as failing_consensus_client,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=failing_coverage_app),
            base_url="http://coverage",
        ) as failing_coverage_client,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_ledger_app(storage=storage)),
            base_url="http://ledger",
        ) as failing_ledger_client,
    ):
        entry_response = await failing_ledger_client.post(
            "/ledger/entries",
            json={
                "observables": ["ioc-1"],
                "evidence": [],
                "attack_techniques": ["T1059"],
                "tlp_label": "TLP:AMBER",
            },
            headers={"Authorization": "Bearer test-ledger-key"},
        )
        entry = entry_response.json()

        await failing_ledger_client.post(
            f"/ledger/entries/{entry['id']}/transitions",
            json={
                "from_state": "suspected",
                "to_state": "confirmed",
                "actor": "consensus",
                "proposal_ids": [],
                "notes": "seed confirmed state",
            },
            headers={"Authorization": "Bearer test-ledger-key"},
        )

        failing_review = await failing_consensus_client.post(
            "/consensus/review_requests",
            json={"entry_id": entry["id"], "reason": "coverage_threshold_exceeded"},
            headers=auth_headers("consensus"),
        )
        assert failing_review.status_code == 502

        for vendor in ("VendorA", "VendorB"):
            ok_response = await failing_coverage_client.post(
                "/coverage/reports",
                json={
                    "entry_id": entry["id"],
                    "vendor": vendor,
                    "detected": True,
                    "timestamp": "2026-04-09T00:00:00Z",
                },
                headers=auth_headers("coverage"),
            )
            assert ok_response.status_code == 201

        failing_coverage = await failing_coverage_client.post(
            "/coverage/reports",
            json={
                "entry_id": entry["id"],
                "vendor": "VendorC",
                "detected": True,
                "timestamp": "2026-04-09T00:00:00Z",
            },
            headers=auth_headers("coverage"),
        )
        assert failing_coverage.status_code == 502
