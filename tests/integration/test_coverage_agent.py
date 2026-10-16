from __future__ import annotations

import pytest

from avchain.agent.worker import EndpointAgentWorker
from avchain.database.core import session_scope
from avchain.models.orm import EntryFeedback
from avchain.models.schemas import TelemetryEvent
from avchain.validator.worker import ValidatorWorker


async def _create_and_confirm_entry(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
) -> dict:
    response = await ledger_client.post(
        "/ledger/entries",
        json=entry_payload,
        headers=auth_headers("ledger"),
    )
    assert response.status_code == 201
    workers = [
        ValidatorWorker(
            validator_id="validator1",
            private_key_path=validator_key_paths["validator1"],
            ledger_client=ledger_client,
            evidence_client=evidence_client,
            consensus_client=consensus_client,
        ),
        ValidatorWorker(
            validator_id="validator2",
            private_key_path=validator_key_paths["validator2"],
            ledger_client=ledger_client,
            evidence_client=evidence_client,
            consensus_client=consensus_client,
        ),
    ]
    for worker in workers:
        await worker.run_once()
    return response.json()


@pytest.mark.asyncio
async def test_coverage_reports_trigger_review(
    ledger_client,
    evidence_client,
    consensus_client,
    coverage_client,
    auth_headers,
    entry_payload,
    coverage_payloads,
    validator_key_paths,
) -> None:
    entry = await _create_and_confirm_entry(
        ledger_client,
        evidence_client,
        consensus_client,
        auth_headers,
        entry_payload,
        validator_key_paths,
    )

    for coverage_payload in coverage_payloads:
        coverage_payload["entry_id"] = entry["id"]
        response = await coverage_client.post(
            "/coverage/reports",
            json=coverage_payload,
            headers=auth_headers("coverage"),
        )
        assert response.status_code == 201

    entry_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    assert entry_response.json()["state"] == "review"


@pytest.mark.asyncio
async def test_agent_generates_feedback_for_matching_telemetry(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    entry_payload,
    telemetry_payloads,
    validator_key_paths,
) -> None:
    entry = await _create_and_confirm_entry(
        ledger_client,
        evidence_client,
        consensus_client,
        auth_headers,
        entry_payload,
        validator_key_paths,
    )

    worker = EndpointAgentWorker(
        ledger_client=ledger_client,
        evidence_client=evidence_client,
    )
    feedback_count = await worker.run_once(
        events=[TelemetryEvent.model_validate(telemetry_payloads[1])]
    )
    assert feedback_count == 1

    entry_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    assert entry_response.status_code == 200
    assert len(entry_response.json()["evidence_digests"]) == 2

    with session_scope() as db:
        assert db.query(EntryFeedback).count() == 1
