from __future__ import annotations

from datetime import datetime

import pytest

from avchain.crypto.keys import canonicalize, load_private_key, sign_message
from avchain.utils.helpers import derive_proposal_id
from avchain.validator.worker import ValidatorWorker


async def _create_entry(
    ledger_client,
    auth_headers,
    entry_payload,
) -> dict:
    response = await ledger_client.post(
        "/ledger/entries",
        json=entry_payload,
        headers=auth_headers("ledger"),
    )
    assert response.status_code == 201
    return response.json()


@pytest.mark.asyncio
async def test_consensus_promotes_after_two_validator_votes(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)
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
        processed = await worker.run_once()
        assert processed == 1

    entry_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    assert entry_response.json()["state"] == "confirmed"

    decisions_response = await consensus_client.get(
        f"/consensus/decisions/{entry['id']}",
        headers=auth_headers("consensus"),
    )
    decisions = decisions_response.json()
    assert len(decisions) == 1
    assert decisions[0]["action"] == "promote"


@pytest.mark.asyncio
async def test_invalid_proposal_is_rejected(
    ledger_client,
    consensus_client,
    auth_headers,
    entry_payload,
    invalid_proposal_payload,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    invalid_proposal_payload["entry_id"] = entry["id"]

    response = await consensus_client.post(
        "/consensus/proposals",
        json=invalid_proposal_payload,
        headers=auth_headers("consensus"),
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_late_third_validator_vote_does_not_duplicate_decisions(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)
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
        assert await worker.run_once() == 1

    entry_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    confirmed_entry = entry_response.json()
    original_updated_at = confirmed_entry["history"][-1]["timestamp"]

    private_key = load_private_key(
        validator_key_paths["validator3"].read_text(encoding="utf-8")
    )
    third_vote = {
        "entry_id": entry["id"],
        "validator_id": "validator3",
        "action": "promote",
        "confidence": 0.9,
        "explanation": "late promote vote",
        "timestamp": original_updated_at,
    }
    third_vote["proposal_id"] = derive_proposal_id(
        entry_id=third_vote["entry_id"],
        validator_id=third_vote["validator_id"],
        timestamp=datetime.fromisoformat(original_updated_at.replace("Z", "+00:00")),
    )
    signature = sign_message(private_key, canonicalize(third_vote))
    late_response = await consensus_client.post(
        "/consensus/proposals",
        json={**third_vote, "signature": signature},
        headers=auth_headers("consensus"),
    )
    assert late_response.status_code == 201

    decisions_response = await consensus_client.get(
        f"/consensus/decisions/{entry['id']}",
        headers=auth_headers("consensus"),
    )
    decisions = decisions_response.json()
    assert len(decisions) == 1

    final_entry_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    history = final_entry_response.json()["history"]
    assert [event["to_state"] for event in history].count("confirmed") == 1


@pytest.mark.asyncio
async def test_mismatched_proposal_id_is_rejected(
    ledger_client,
    consensus_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    proposal = {
        "proposal_id": "not-the-derived-id",
        "entry_id": entry["id"],
        "validator_id": "validator1",
        "action": "promote",
        "confidence": 0.9,
        "explanation": "proposal id mismatch",
        "timestamp": entry["updated_at"],
    }
    private_key = load_private_key(
        validator_key_paths["validator1"].read_text(encoding="utf-8")
    )
    signature = sign_message(private_key, canonicalize(proposal))
    response = await consensus_client.post(
        "/consensus/proposals",
        json={**proposal, "signature": signature},
        headers=auth_headers("consensus"),
    )
    assert response.status_code == 400
