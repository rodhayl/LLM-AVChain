from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256

import httpx
import pytest

from avchain.agent.worker import EndpointAgentWorker
from avchain.models.enums import LifecycleState, ProposalAction
from avchain.models.schemas import TelemetryEvent
from avchain.validator.worker import ValidatorWorker


async def _create_entry(ledger_client, auth_headers, entry_payload) -> dict:
    response = await ledger_client.post(
        "/ledger/entries",
        json=entry_payload,
        headers=auth_headers("ledger"),
    )
    assert response.status_code == 201
    return response.json()


@pytest.mark.asyncio
async def test_validator_worker_skips_cached_entries_and_handles_missing_evidence(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
) -> None:
    created_entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    worker = ValidatorWorker(
        validator_id="validator1",
        private_key_path=validator_key_paths["validator1"],
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        consensus_client=consensus_client,
    )

    assert await worker.fetch_evidence("missing-digest") is None
    assert await worker.run_once() == 1
    assert await worker.run_once() == 0
    entries = await worker.poll_entries(LifecycleState.SUSPECTED)
    proposal_id = worker.compute_proposal_id(
        entry_id=str(entries[0].id),
        timestamp=datetime(2026, 4, 9, tzinfo=UTC),
    )
    assert len(proposal_id) == 16
    assert str(entries[0].id) == created_entry["id"]


@pytest.mark.asyncio
async def test_validator_submit_proposal_raises_on_rejected_response(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
) -> None:
    created_entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    worker = ValidatorWorker(
        validator_id="validator1",
        private_key_path=validator_key_paths["validator1"],
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        consensus_client=consensus_client,
    )
    worker.consensus_api_key = "wrong-key"
    entry = await worker.poll_entries(LifecycleState.SUSPECTED)
    with pytest.raises(httpx.HTTPStatusError):
        await worker.submit_proposal(
            entry=entry[0],
            action=ProposalAction.PROMOTE,
            confidence=0.9,
            explanation="retry branch",
        )
    assert created_entry["id"] == str(entry[0].id)


@pytest.mark.asyncio
async def test_validator_submit_proposal_uses_generation_timestamp_for_contract(
    ledger_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    fixed_timestamp = datetime(2026, 4, 9, 12, 0, 0, tzinfo=UTC)
    captured_payload: dict[str, object] = {}

    class CaptureConsensusClient:
        async def post(self, url: str, json: dict, headers: dict) -> httpx.Response:
            _ = headers
            assert url == "/consensus/proposals"
            captured_payload.update(json)
            return httpx.Response(
                201,
                json=json,
                request=httpx.Request("POST", f"http://testserver{url}"),
            )

    worker = ValidatorWorker(
        validator_id="validator1",
        private_key_path=validator_key_paths["validator1"],
        ledger_client=ledger_client,
        consensus_client=CaptureConsensusClient(),
    )
    monkeypatch.setattr(
        "avchain.validator.worker.current_timestamp",
        lambda: fixed_timestamp,
    )

    entry = await worker.poll_entries(LifecycleState.SUSPECTED)
    await worker.submit_proposal(
        entry=entry[0],
        action=ProposalAction.PROMOTE,
        confidence=0.9,
        explanation="contract proof",
    )

    expected_id = sha256(
        f"{created_entry['id']}:validator1:{fixed_timestamp.isoformat()}".encode()
    ).hexdigest()[:16]
    assert captured_payload["timestamp"] == fixed_timestamp.isoformat().replace(
        "+00:00", "Z"
    )
    assert captured_payload["proposal_id"] == expected_id


@pytest.mark.asyncio
async def test_agent_worker_branches_and_status(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
) -> None:
    worker = EndpointAgentWorker(
        ledger_client=ledger_client,
        evidence_client=evidence_client,
    )

    benign_event = worker.generate_telemetry_event()
    assert benign_event.observable.startswith("benign-")
    assert (
        await worker.process_event(
            TelemetryEvent(observable="no-match", metadata={"file_path": "C:/Temp/x"})
        )
        is None
    )
    assert worker.status()["events_processed"] == 1

    created_entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    validator = ValidatorWorker(
        validator_id="validator1",
        private_key_path=validator_key_paths["validator1"],
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        consensus_client=consensus_client,
    )
    second_validator = ValidatorWorker(
        validator_id="validator2",
        private_key_path=validator_key_paths["validator2"],
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        consensus_client=consensus_client,
    )
    await validator.run_once()
    await second_validator.run_once()

    await worker.refresh_confirmed_entries()
    cached_entry_id = next(iter(worker.confirmed_entries))
    malicious_event = worker._build_event_batch()[0]
    assert malicious_event.observable in worker.confirmed_entries[cached_entry_id]

    feedback_count = await worker.run_once(events=[malicious_event])
    assert feedback_count == 1
    status = worker.status()
    assert status["confirmed_entries_cached"] == 1
    assert status["feedback_generated"] == 1
    cached_ids = {str(entry_id) for entry_id in worker.confirmed_entries}
    assert created_entry["id"] in cached_ids
