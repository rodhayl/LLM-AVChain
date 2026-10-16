from __future__ import annotations

from datetime import timedelta

import pytest

from avchain.agent.worker import EndpointAgentWorker
from avchain.database.core import session_scope
from avchain.ledger.crud import run_timeout_transitions
from avchain.models.orm import Entry, EntryFeedback
from avchain.models.schemas import TelemetryEvent
from avchain.utils.helpers import current_timestamp
from avchain.validator.worker import ValidatorWorker


async def _create_entry(ledger_client, auth_headers, entry_payload) -> dict:
    response = await ledger_client.post(
        "/ledger/entries",
        json=entry_payload,
        headers=auth_headers("ledger"),
    )
    assert response.status_code == 201
    return response.json()


async def _run_validators(
    ledger_client,
    evidence_client,
    consensus_client,
    validator_key_paths,
) -> None:
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


@pytest.mark.asyncio
async def test_s1_promotion_and_feedback_loop(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    entry_payload,
    telemetry_payloads,
    validator_key_paths,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    await _run_validators(
        ledger_client,
        evidence_client,
        consensus_client,
        validator_key_paths,
    )

    agent = EndpointAgentWorker(
        ledger_client=ledger_client,
        evidence_client=evidence_client,
    )
    feedback_count = await agent.run_once(
        events=[TelemetryEvent.model_validate(telemetry_payloads[1])]
    )
    assert feedback_count == 1

    entry_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    assert entry_response.json()["state"] == "confirmed"

    with session_scope() as db:
        assert db.query(EntryFeedback).count() == 1


@pytest.mark.asyncio
async def test_s2_timeout_driven_deprecation(
    ledger_client,
    auth_headers,
    entry_payload,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)

    with session_scope() as db:
        entry_row = db.query(Entry).filter(Entry.id == entry["id"]).one()
        entry_row.updated_at = current_timestamp() - timedelta(hours=2)
        run_timeout_transitions(
            db=db,
            suspected_timeout_hours=0.001,
            review_timeout_hours=0.001,
            now=current_timestamp(),
        )

    with session_scope() as db:
        entry_row = db.query(Entry).filter(Entry.id == entry["id"]).one()
        entry_row.updated_at = current_timestamp() - timedelta(hours=2)
        run_timeout_transitions(
            db=db,
            suspected_timeout_hours=0.001,
            review_timeout_hours=0.001,
            now=current_timestamp(),
        )

    final_entry = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    body = final_entry.json()
    assert body["state"] == "deprecated"
    assert [event["to_state"] for event in body["history"]][-2:] == [
        "review",
        "deprecated",
    ]


@pytest.mark.asyncio
async def test_s3_coverage_triggered_revalidation(
    ledger_client,
    evidence_client,
    consensus_client,
    coverage_client,
    auth_headers,
    entry_payload,
    coverage_payloads,
    validator_key_paths,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    await _run_validators(
        ledger_client,
        evidence_client,
        consensus_client,
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

    review_entry = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    assert review_entry.json()["state"] == "review"

    await _run_validators(
        ledger_client,
        evidence_client,
        consensus_client,
        validator_key_paths,
    )

    reconfirmed_entry = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    assert reconfirmed_entry.json()["state"] == "confirmed"
