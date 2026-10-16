from uuid import UUID, uuid4

import httpx
import pytest

from avchain.agent.worker import EndpointAgentWorker
from avchain.coverage.central import SimulatedExternalCoverage
from avchain.database.core import session_scope
from avchain.models.orm import CentralCheckEvent
from avchain.scripts.run_central_demo import run_demo


async def confirmed(ledger_client, auth_headers):
    response = await ledger_client.post(
        "/ledger/entries",
        headers=auth_headers("ledger"),
        json={"observables": ["a" * 64]},
    )
    entry_id = UUID(response.json()["id"])
    response = await ledger_client.post(
        f"/ledger/entries/{entry_id}/transitions",
        headers=auth_headers("ledger"),
        json={"from_state": "suspected", "to_state": "confirmed", "actor": "test"},
    )
    assert response.status_code == 200
    return entry_id


async def test_minimal_data_demo_round_trip_and_replay(test_environment):
    report = await run_demo()
    assert report["status"] == "PASS"
    assert report["real_vendor_integration"] is False
    assert report["local_antivirus_required"] is False
    assert report["events_stored"] == 2
    assert report["coverage_source"] == "SIMULATED"


async def test_authenticated_control_conflict_and_old_event_replay(
    ledger_client, auth_headers
):
    entry_id = await confirmed(ledger_client, auth_headers)
    event_id = uuid4()
    feed = SimulatedExternalCoverage(ledger_client, "test-ledger-key")
    first = await feed.report(event_id, entry_id, covered=True)
    assert first["replayed"] is False
    assert (await feed.report(event_id, entry_id, covered=True))["replayed"] is True
    with pytest.raises(httpx.HTTPStatusError):
        await feed.report(event_id, entry_id, covered=False)
    await feed.report(uuid4(), entry_id, covered=False)
    await feed.report(event_id, entry_id, covered=True)
    snapshot = await ledger_client.get("/ledger/checks", headers=auth_headers("ledger"))
    assert snapshot.json()[0]["active"] is True
    assert snapshot.json()[0]["source"] == "SIMULATED_EXTERNAL_COVERAGE"
    assert snapshot.json()[0]["reason"] == "SIMULATED external feed: coverage withdrawn"
    with session_scope() as db:
        assert db.query(CentralCheckEvent).count() == 2
    unauthenticated = await ledger_client.get("/ledger/checks")
    assert unauthenticated.status_code == 401
    invalid = await ledger_client.post(
        "/ledger/checks/events",
        headers=auth_headers("ledger"),
        json={
            "event_id": str(uuid4()),
            "entry_id": str(entry_id),
            "active": False,
            "reason": "wrong",
            "source": "CENTRAL_REACTIVATION",
        },
    )
    assert invalid.status_code == 400


async def test_sync_outage_restores_cached_checks(ledger_client, auth_headers):
    entry_id = await confirmed(ledger_client, auth_headers)
    worker = EndpointAgentWorker(ledger_client=ledger_client, central_demo=True)
    await worker.refresh_confirmed_entries()
    feed = SimulatedExternalCoverage(ledger_client, "test-ledger-key")
    await feed.report(uuid4(), entry_id, covered=True)
    await worker.refresh_confirmed_entries()
    assert entry_id not in worker.confirmed_entries
    worker._artifact_state.mark_processed("unchanged")
    async with httpx.AsyncClient(
        base_url="http://offline",
        transport=httpx.MockTransport(lambda request: httpx.Response(503)),
    ) as broken:
        worker._ledger_client = broken
        await worker.refresh_confirmed_entries()
        assert entry_id in worker.confirmed_entries
        assert worker.central_sync_error == "HTTPStatusError"
        assert not worker._artifact_state.has_processed("unchanged")
        cold = EndpointAgentWorker(ledger_client=broken, central_demo=True)
        with pytest.raises(httpx.HTTPStatusError):
            await cold.refresh_confirmed_entries()


async def test_tampered_central_evidence_does_not_keep_checks_disabled(
    ledger_client, auth_headers, storage
):
    entry_id = await confirmed(ledger_client, auth_headers)
    worker = EndpointAgentWorker(ledger_client=ledger_client, central_demo=True)
    feed = SimulatedExternalCoverage(ledger_client, "test-ledger-key")
    event = await feed.report(uuid4(), entry_id, covered=True)
    await worker.refresh_confirmed_entries()
    assert entry_id not in worker.confirmed_entries
    storage._path_for(event["evidence_digest"]).write_bytes(b"corrupted")
    await worker.refresh_confirmed_entries()
    assert entry_id in worker.confirmed_entries
    assert worker.central_sync_error == "HTTPStatusError"


async def test_central_reactivation_never_revives_deprecated_entry(
    ledger_client, auth_headers
):
    entry_id = await confirmed(ledger_client, auth_headers)
    for before, after in (("confirmed", "review"), ("review", "deprecated")):
        result = await ledger_client.post(
            f"/ledger/entries/{entry_id}/transitions",
            headers=auth_headers("ledger"),
            json={
                "from_state": before,
                "to_state": after,
                "actor": "consensus",
                "notes": "false positive",
            },
        )
        assert result.status_code == 200
    response = await ledger_client.post(
        "/ledger/checks/events",
        headers=auth_headers("ledger"),
        json={
            "event_id": str(uuid4()),
            "entry_id": str(entry_id),
            "active": True,
            "reason": "operator reactivation",
            "source": "CENTRAL_REACTIVATION",
        },
    )
    assert response.status_code == 409
    response = await ledger_client.get("/ledger/checks", headers=auth_headers("ledger"))
    assert response.json() == []


async def test_contradictory_snapshot_never_activates_deprecated(test_environment):
    from avchain.models.schemas import ThreatEntry

    entry = ThreatEntry(observables=["a" * 64], state="deprecated")
    response = [
        {
            "entry": entry.model_dump(mode="json"),
            "active": True,
            "reason": "contradictory response",
            "source": "DEFAULT",
        }
    ]
    async with httpx.AsyncClient(
        base_url="http://central",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=response)
        ),
    ) as client:
        worker = EndpointAgentWorker(ledger_client=client, central_demo=True)
        await worker.refresh_confirmed_entries()
        assert entry.id not in worker.confirmed_entries
