from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from avchain.database.core import session_scope
from avchain.ledger.crud import run_timeout_transitions
from avchain.models.enums import ProposalAction
from avchain.models.orm import Entry, Proposal
from avchain.utils.helpers import current_timestamp


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
async def test_create_entry_and_fetch_evidence(
    ledger_client,
    evidence_client,
    auth_headers,
    entry_payload,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    assert entry["state"] == "suspected"
    assert len(entry["evidence_digests"]) == 1

    list_response = await evidence_client.get(
        f"/evidence/entries/{entry['id']}",
        headers=auth_headers("evidence"),
    )
    assert list_response.status_code == 200
    evidence_items = list_response.json()
    assert len(evidence_items) == 1

    digest = evidence_items[0]["digest"]
    fetch_response = await evidence_client.get(
        f"/evidence/{digest}",
        headers=auth_headers("evidence"),
    )
    assert fetch_response.status_code == 200
    assert fetch_response.content


@pytest.mark.asyncio
async def test_invalid_transition_rejected(
    ledger_client,
    auth_headers,
    entry_payload,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    response = await ledger_client.post(
        f"/ledger/entries/{entry['id']}/transitions",
        json={
            "from_state": "confirmed",
            "to_state": "deprecated",
            "actor": "consensus",
            "proposal_ids": [],
        },
        headers=auth_headers("ledger"),
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_feedback_requires_confirmed_state(
    ledger_client,
    evidence_client,
    auth_headers,
    entry_payload,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)
    digest = entry["evidence_digests"][0]

    rejected = await ledger_client.post(
        f"/ledger/entries/{entry['id']}/feedback",
        json={"digest": digest},
        headers=auth_headers("ledger"),
    )
    assert rejected.status_code == 400

    promoted = await ledger_client.post(
        f"/ledger/entries/{entry['id']}/transitions",
        json={
            "from_state": "suspected",
            "to_state": "confirmed",
            "actor": "consensus",
            "proposal_ids": ["proposal-1", "proposal-2"],
        },
        headers=auth_headers("ledger"),
    )
    assert promoted.status_code == 200

    reused_digest = await ledger_client.post(
        f"/ledger/entries/{entry['id']}/feedback",
        json={"digest": digest},
        headers=auth_headers("ledger"),
    )
    assert reused_digest.status_code == 400

    evidence_response = await evidence_client.post(
        "/evidence",
        json={
            "entry_id": entry["id"],
            "data": {
                "feedback_id": str(uuid4()),
                "entry_id": entry["id"],
                "hashed_identifiers": {
                    "file_path": "hashed-path",
                    "process_name": "hashed-process",
                    "host": "hashed-host",
                },
                "action_taken": "log",
                "timestamp": "2026-04-09T00:00:00Z",
            },
        },
        headers={**auth_headers("evidence"), "Content-Type": "application/json"},
    )
    assert evidence_response.status_code == 201

    accepted = await ledger_client.post(
        f"/ledger/entries/{entry['id']}/feedback",
        json={"digest": evidence_response.json()["digest"]},
        headers=auth_headers("ledger"),
    )
    assert accepted.status_code == 201


@pytest.mark.asyncio
async def test_multipart_json_feedback_is_classified_as_feedback(
    ledger_client,
    evidence_client,
    auth_headers,
    entry_payload,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)

    promoted = await ledger_client.post(
        f"/ledger/entries/{entry['id']}/transitions",
        json={
            "from_state": "suspected",
            "to_state": "confirmed",
            "actor": "consensus",
            "proposal_ids": ["proposal-1", "proposal-2"],
        },
        headers=auth_headers("ledger"),
    )
    assert promoted.status_code == 200

    multipart_feedback = {
        "feedback_id": str(uuid4()),
        "entry_id": entry["id"],
        "hashed_identifiers": {
            "file_path": "hashed-path",
            "process_name": "hashed-process",
            "host": "hashed-host",
        },
        "action_taken": "log",
        "timestamp": "2026-04-09T00:00:00Z",
    }
    evidence_response = await evidence_client.post(
        "/evidence",
        headers=auth_headers("evidence"),
        data={"entry_id": entry["id"]},
        files={
            "file": (
                "feedback.json",
                json.dumps(multipart_feedback).encode("utf-8"),
                "application/json",
            )
        },
    )
    assert evidence_response.status_code == 201

    accepted = await ledger_client.post(
        f"/ledger/entries/{entry['id']}/feedback",
        json={"digest": evidence_response.json()["digest"]},
        headers=auth_headers("ledger"),
    )
    assert accepted.status_code == 201


@pytest.mark.asyncio
async def test_timeout_transitions_progress_to_review_and_deprecated(
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

    review_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    assert review_response.json()["state"] == "review"

    with session_scope() as db:
        entry_row = db.query(Entry).filter(Entry.id == entry["id"]).one()
        entry_row.updated_at = current_timestamp() - timedelta(hours=2)
        run_timeout_transitions(
            db=db,
            suspected_timeout_hours=0.001,
            review_timeout_hours=0.001,
            now=current_timestamp(),
        )

    deprecated_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    assert deprecated_response.json()["state"] == "deprecated"


@pytest.mark.asyncio
async def test_shared_evidence_digest_lists_for_all_linked_entries(
    ledger_client,
    evidence_client,
    auth_headers,
) -> None:
    shared_payload = {
        "observables": ["ioc-shared"],
        "evidence": [
            {
                "content_type": "application/json",
                "data": {"shared": True, "sample": "same-payload"},
            }
        ],
        "attack_techniques": ["T1059"],
        "tlp_label": "TLP:AMBER",
    }

    first_entry = await _create_entry(ledger_client, auth_headers, shared_payload)
    second_entry = await _create_entry(ledger_client, auth_headers, shared_payload)

    first_evidence = await evidence_client.get(
        f"/evidence/entries/{first_entry['id']}",
        headers=auth_headers("evidence"),
    )
    second_evidence = await evidence_client.get(
        f"/evidence/entries/{second_entry['id']}",
        headers=auth_headers("evidence"),
    )

    assert len(first_evidence.json()) == 1
    assert len(second_evidence.json()) == 1
    assert first_evidence.json()[0]["digest"] == second_evidence.json()[0]["digest"]


@pytest.mark.asyncio
async def test_stale_review_proposals_do_not_block_timeout_deprecation(
    ledger_client,
    auth_headers,
    entry_payload,
) -> None:
    entry = await _create_entry(ledger_client, auth_headers, entry_payload)

    promoted = await ledger_client.post(
        f"/ledger/entries/{entry['id']}/transitions",
        json={
            "from_state": "suspected",
            "to_state": "review",
            "actor": "timeout",
            "proposal_ids": [],
            "notes": "seed review state",
        },
        headers=auth_headers("ledger"),
    )
    assert promoted.status_code == 200

    with session_scope() as db:
        entry_row = db.query(Entry).filter(Entry.id == entry["id"]).one()
        entry_row.updated_at = current_timestamp() - timedelta(hours=2)
        db.add(
            Proposal(
                proposal_id=f"stale-retain-{uuid4()}",
                entry_id=entry["id"],
                validator_id="validator1",
                action=ProposalAction.RETAIN.value,
                confidence=0.9,
                explanation="stale retain",
                timestamp=current_timestamp() - timedelta(hours=1),
                signature="sig",
            )
        )

    with session_scope() as db:
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
    assert final_entry.json()["state"] == "deprecated"
