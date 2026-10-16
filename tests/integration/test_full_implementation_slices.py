from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from avchain.agent.worker import EndpointAgentWorker
from avchain.endpoint.registry import reset_endpoint_registry_cache
from avchain.ledger.service import create_app as create_ledger_app
from avchain.models.enums import ProposalAction
from avchain.models.orm import EntryFeedback
from avchain.models.orm import Proposal as ProposalORM
from avchain.models.schemas import ThreatEntryCreate
from avchain.scripts.generate_keys import generate_endpoint_material
from avchain.validator.heuristics import LMStudioAnalysisStrategy
from avchain.validator.worker import ValidatorWorker


class FakeValidatorLLMClient:
    async def analyze_validator_evidence(
        self,
        *,
        observables: list[str],
        evidence_summaries: list[str],
    ) -> object:
        _ = observables, evidence_summaries
        from avchain.llm.schemas import ValidatorAnalysisOutput

        return ValidatorAnalysisOutput(
            action=ProposalAction.PROMOTE,
            confidence=0.87,
            reasoning_summary="Structured local LLM promotion",
            attack_techniques=["T1059"],
            evidence_gaps=[],
        )


async def _create_entry(ledger_client, auth_headers, payload: dict) -> dict:
    response = await ledger_client.post(
        "/ledger/entries",
        json=payload,
        headers=auth_headers("ledger"),
    )
    assert response.status_code == 201
    return response.json()


async def _transition_entry(
    ledger_client,
    auth_headers,
    *,
    entry_id: str,
    from_state: str,
    to_state: str,
    actor: str,
    notes: str,
) -> dict:
    response = await ledger_client.post(
        f"/ledger/entries/{entry_id}/transitions",
        json={
            "from_state": from_state,
            "to_state": to_state,
            "actor": actor,
            "proposal_ids": [],
            "notes": notes,
        },
        headers=auth_headers("ledger"),
    )
    assert response.status_code == 200
    return response.json()


@pytest.mark.asyncio
async def test_validator_proposal_provenance_is_persisted(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    validator_key_paths,
    db_session,
) -> None:
    payload = ThreatEntryCreate(
        observables=["provenance-ioc-a"],
        evidence=[{"content_type": "application/json", "data": {"signal": "x"}}],
        tlp_label="TLP:CLEAR",
    ).model_dump(mode="json")
    entry = await _create_entry(ledger_client, auth_headers, payload)

    worker = ValidatorWorker(
        validator_id="validator1",
        private_key_path=validator_key_paths["validator1"],
        strategy=LMStudioAnalysisStrategy(client=FakeValidatorLLMClient()),
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        consensus_client=consensus_client,
    )

    processed = await worker.run_once()
    proposal = (
        db_session.query(ProposalORM).order_by(ProposalORM.timestamp.desc()).first()
    )

    assert processed == 1
    assert proposal is not None
    assert proposal.analysis_backend == "llm_lmstudio"
    assert proposal.llm_provider == "lmstudio"
    assert proposal.prompt_name == "validator_triage"
    assert proposal.prompt_version == "v1"

    proposals_response = await consensus_client.get(
        f"/consensus/proposals/{entry['id']}",
        headers=auth_headers("consensus"),
    )
    assert proposals_response.status_code == 200
    assert proposals_response.json()[0]["provenance"]["analysis_backend"] == (
        "llm_lmstudio"
    )


@pytest.mark.asyncio
async def test_review_records_open_and_can_reconfirm_entries(
    ledger_client,
    auth_headers,
) -> None:
    entry = await _create_entry(
        ledger_client,
        auth_headers,
        ThreatEntryCreate(
            observables=["review-ioc-a"],
            evidence=[],
            tlp_label="TLP:CLEAR",
        ).model_dump(mode="json"),
    )
    await _transition_entry(
        ledger_client,
        auth_headers,
        entry_id=entry["id"],
        from_state="suspected",
        to_state="confirmed",
        actor="consensus",
        notes="seed confirmed entry",
    )
    await _transition_entry(
        ledger_client,
        auth_headers,
        entry_id=entry["id"],
        from_state="confirmed",
        to_state="review",
        actor="oracle",
        notes="coverage-triggered revalidation",
    )

    review_records_response = await ledger_client.get(
        "/review/records",
        params={"entry_id": entry["id"]},
        headers=auth_headers("ledger"),
    )
    assert review_records_response.status_code == 200
    review_record = review_records_response.json()[0]
    assert review_record["status"] == "open"

    assign_response = await ledger_client.post(
        f"/review/records/{review_record['review_id']}/assign",
        json={"assigned_to": "analyst-queue-a", "actor": "supervisor"},
        headers=auth_headers("ledger"),
    )
    assert assign_response.status_code == 200
    assert assign_response.json()["assigned_to"] == "analyst-queue-a"

    approve_response = await ledger_client.post(
        f"/review/records/{review_record['review_id']}/actions",
        json={
            "action": "approve_confirmed",
            "actor": "analyst",
            "notes": "human review completed",
        },
        headers=auth_headers("ledger"),
    )
    assert approve_response.status_code == 200
    assert approve_response.json()["status"] == "approved"

    note_response = await ledger_client.post(
        f"/review/records/{review_record['review_id']}/notes",
        json={
            "author": "analyst",
            "note": "Evidence inspected and approved for reconfirmation.",
        },
        headers=auth_headers("ledger"),
    )
    assert note_response.status_code == 201
    assert note_response.json()["author"] == "analyst"

    entry_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}",
        headers=auth_headers("ledger"),
    )
    assert entry_response.status_code == 200
    assert entry_response.json()["state"] == "confirmed"

    context_response = await ledger_client.get(
        f"/review/records/{review_record['review_id']}/context",
        headers=auth_headers("ledger"),
    )
    assert context_response.status_code == 200
    assert context_response.json()["review"]["review_id"] == review_record["review_id"]
    assert context_response.json()["entry"]["id"] == entry["id"]
    assert len(context_response.json()["notes"]) >= 3

    notes_response = await ledger_client.get(
        f"/review/records/{review_record['review_id']}/notes",
        headers=auth_headers("ledger"),
    )
    assert notes_response.status_code == 200
    assert any(
        note["note"] == "Evidence inspected and approved for reconfirmation."
        for note in notes_response.json()
    )

    reviewer_packet_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}/reviewer_packet",
        headers=auth_headers("ledger"),
    )
    assert reviewer_packet_response.status_code == 200
    reviewer_packet = reviewer_packet_response.json()
    assert reviewer_packet["entry"]["id"] == entry["id"]
    assert reviewer_packet["proof_points"]["has_review_records"] is True
    assert reviewer_packet["stix_summary"]["object_count"] >= 3


@pytest.mark.asyncio
async def test_stix_export_endpoint_returns_bundle(
    ledger_client,
    auth_headers,
) -> None:
    entry = await _create_entry(
        ledger_client,
        auth_headers,
        ThreatEntryCreate(
            observables=["example.org", "behavior:powershell-download"],
            evidence=[],
            attack_techniques=["T1059"],
            tlp_label="TLP:AMBER",
        ).model_dump(mode="json"),
    )

    response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}/stix",
        headers=auth_headers("ledger"),
    )

    assert response.status_code == 200
    bundle = response.json()
    assert bundle["type"] == "bundle"
    assert any(obj["type"] == "indicator" for obj in bundle["objects"])


@pytest.mark.asyncio
async def test_stix_import_preview_endpoint_round_trips_exported_bundle(
    ledger_client,
    auth_headers,
) -> None:
    entry = await _create_entry(
        ledger_client,
        auth_headers,
        ThreatEntryCreate(
            observables=["preview.example", "behavior:powershell-download"],
            evidence=[],
            attack_techniques=["T1059"],
            tlp_label="TLP:AMBER",
        ).model_dump(mode="json"),
    )
    export_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}/stix",
        headers=auth_headers("ledger"),
    )
    preview_response = await ledger_client.post(
        "/stix/import/preview",
        json=export_response.json(),
        headers=auth_headers("ledger"),
    )

    assert preview_response.status_code == 200
    preview = preview_response.json()
    assert "preview.example" in preview["observables"]
    assert preview["attack_techniques"] == ["T1059"]
    assert preview["tlp_label"] == "TLP:AMBER"


@pytest.mark.asyncio
async def test_stix_import_endpoint_creates_entry_from_bundle(
    ledger_client,
    auth_headers,
) -> None:
    entry = await _create_entry(
        ledger_client,
        auth_headers,
        ThreatEntryCreate(
            observables=["import-create.example", "behavior:powershell-download"],
            evidence=[],
            attack_techniques=["T1059"],
            tlp_label="TLP:AMBER",
        ).model_dump(mode="json"),
    )
    export_response = await ledger_client.get(
        f"/ledger/entries/{entry['id']}/stix",
        headers=auth_headers("ledger"),
    )
    import_response = await ledger_client.post(
        "/stix/import",
        json=export_response.json(),
        headers=auth_headers("ledger"),
    )

    assert import_response.status_code == 201
    imported = import_response.json()
    assert "import-create.example" in imported["observables"]
    assert imported["evidence_digests"]


@pytest.mark.asyncio
async def test_taxii_publish_endpoint_uses_configured_collection(
    storage,
    auth_headers,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TAXII_BASE_URL", "http://taxii.example")
    monkeypatch.setenv("TAXII_COLLECTION_ID", "demo-collection")
    monkeypatch.setenv("TAXII_API_KEY", "taxii-token")
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    captured: dict[str, object] = {}

    async def fake_publish_bundle(self, *, collection_id: str, bundle: dict) -> dict:
        captured["base_url"] = self.base_url
        captured["collection_id"] = collection_id
        captured["bundle"] = bundle
        return {"status": "accepted"}

    monkeypatch.setattr(
        "avchain.ledger.service.TaxiiClient.publish_bundle",
        fake_publish_bundle,
    )
    app = create_ledger_app(storage=storage)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://ledger",
    ) as client:
        entry = await _create_entry(
            client,
            auth_headers,
            ThreatEntryCreate(
                observables=["publish.example"],
                evidence=[],
                tlp_label="TLP:CLEAR",
            ).model_dump(mode="json"),
        )
        response = await client.post(
            f"/ledger/entries/{entry['id']}/taxii/publish",
            headers=auth_headers("ledger"),
        )

    assert response.status_code == 200
    assert response.json()["collection_id"] == "demo-collection"
    assert captured["base_url"] == "http://taxii.example"
    assert captured["collection_id"] == "demo-collection"


@pytest.mark.asyncio
async def test_taxii_collection_preview_endpoint_fetches_remote_bundle(
    storage,
    auth_headers,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TAXII_BASE_URL", "http://taxii.example")
    monkeypatch.setenv("TAXII_COLLECTION_ID", "demo-collection")
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    bundle = {
        "type": "bundle",
        "id": "bundle--demo",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--demo",
                "pattern_type": "stix",
                "pattern": "[domain-name:value = 'preview-taxii.example']",
            }
        ],
    }

    async def fake_fetch_collection_objects(
        self,
        *,
        collection_id: str,
    ) -> dict[str, object]:
        assert self.base_url == "http://taxii.example"
        assert collection_id == "demo-collection"
        return bundle

    monkeypatch.setattr(
        "avchain.ledger.service.TaxiiClient.fetch_collection_objects",
        fake_fetch_collection_objects,
    )
    app = create_ledger_app(storage=storage)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://ledger",
    ) as client:
        response = await client.get(
            "/taxii/collections/demo-collection/preview",
            headers=auth_headers("ledger"),
        )

    assert response.status_code == 200
    assert "preview-taxii.example" in response.json()["observables"]


@pytest.mark.asyncio
async def test_taxii_collection_import_endpoint_creates_entry(
    storage,
    auth_headers,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TAXII_BASE_URL", "http://taxii.example")
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    bundle = {
        "type": "bundle",
        "id": "bundle--demo",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--demo",
                "pattern_type": "stix",
                "pattern": "[domain-name:value = 'import-taxii.example']",
            }
        ],
    }

    async def fake_fetch_collection_objects(
        self,
        *,
        collection_id: str,
    ) -> dict[str, object]:
        assert collection_id == "demo-collection"
        return bundle

    monkeypatch.setattr(
        "avchain.ledger.service.TaxiiClient.fetch_collection_objects",
        fake_fetch_collection_objects,
    )
    app = create_ledger_app(storage=storage)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://ledger",
    ) as client:
        response = await client.post(
            "/taxii/collections/demo-collection/import",
            headers=auth_headers("ledger"),
        )

    assert response.status_code == 200
    assert "import-taxii.example" in response.json()["observables"]
    assert response.json()["evidence_digests"]


@pytest.mark.asyncio
async def test_endpoint_worker_reads_external_telemetry_collectors(
    ledger_client,
    evidence_client,
    auth_headers,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = await _create_entry(
        ledger_client,
        auth_headers,
        ThreatEntryCreate(
            observables=["process:setup.exe"],
            evidence=[],
            tlp_label="TLP:CLEAR",
        ).model_dump(mode="json"),
    )
    await _transition_entry(
        ledger_client,
        auth_headers,
        entry_id=entry["id"],
        from_state="suspected",
        to_state="confirmed",
        actor="consensus",
        notes="seed confirmed entry",
    )

    process_events_path = tmp_path / "process_events.jsonl"
    process_events_path.write_text(
        json.dumps(
            {
                "observable": "process:setup.exe",
                "metadata": {
                    "process_name": "setup.exe",
                    "host": "demo-endpoint",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("ENDPOINT_PROCESS_EVENTS_PATH", process_events_path.as_posix())
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    worker = EndpointAgentWorker(
        ledger_client=ledger_client,
        evidence_client=evidence_client,
    )

    generated = await worker.run_once()

    assert generated == 1
    assert worker.last_matched_entry_id == entry["id"]


@pytest.mark.asyncio
async def test_endpoint_high_impact_action_routes_to_review_queue(
    ledger_client,
    evidence_client,
    auth_headers,
    entry_payload,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir(parents=True, exist_ok=True)
    watched_file = watch_dir / "simulant.txt"
    watched_file.write_text("benign direct-match simulant", encoding="utf-8")
    quarantine_dir = tmp_path / "quarantine"

    from avchain.utils.helpers import compute_sha256

    digest = compute_sha256(watched_file.read_bytes())
    direct_payload = dict(entry_payload)
    direct_payload["observables"] = [digest]
    entry = await _create_entry(ledger_client, auth_headers, direct_payload)
    await _transition_entry(
        ledger_client,
        auth_headers,
        entry_id=entry["id"],
        from_state="suspected",
        to_state="confirmed",
        actor="consensus",
        notes="seed confirmed entry",
    )

    monkeypatch.setenv("ENDPOINT_SCAN_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_WATCH_DIR", watch_dir.as_posix())
    monkeypatch.setenv("ENDPOINT_QUARANTINE_DIR", quarantine_dir.as_posix())
    monkeypatch.setenv("REMEDIATION_ACTION", "quarantine")
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    worker = EndpointAgentWorker(
        ledger_client=ledger_client,
        evidence_client=evidence_client,
    )

    generated = await worker.run_once(events=[])
    review_records_response = await ledger_client.get(
        "/review/records",
        params={"entry_id": entry["id"]},
        headers=auth_headers("ledger"),
    )

    assert generated == 1
    assert not (quarantine_dir / watched_file.name).exists()
    assert review_records_response.status_code == 200
    assert review_records_response.json()[0]["requested_by"] == "endpoint-agent"


@pytest.mark.asyncio
async def test_feedback_metadata_is_denormalized_into_entry_feedback_rows(
    ledger_client,
    evidence_client,
    auth_headers,
    entry_payload,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    db_session,
) -> None:
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir(parents=True, exist_ok=True)
    watched_file = watch_dir / "simulant.txt"
    watched_file.write_text("benign direct-match simulant", encoding="utf-8")

    from avchain.utils.helpers import compute_sha256

    digest = compute_sha256(watched_file.read_bytes())
    direct_payload = dict(entry_payload)
    direct_payload["observables"] = [digest]
    entry = await _create_entry(ledger_client, auth_headers, direct_payload)
    await _transition_entry(
        ledger_client,
        auth_headers,
        entry_id=entry["id"],
        from_state="suspected",
        to_state="confirmed",
        actor="consensus",
        notes="seed confirmed entry",
    )

    monkeypatch.setenv("ENDPOINT_SCAN_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_WATCH_DIR", watch_dir.as_posix())
    monkeypatch.setenv("REMEDIATION_ACTION", "alert")
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    worker = EndpointAgentWorker(
        ledger_client=ledger_client,
        evidence_client=evidence_client,
    )

    generated = await worker.run_once(events=[])
    feedback_row = (
        db_session.query(EntryFeedback).order_by(EntryFeedback.timestamp.desc()).first()
    )

    assert generated == 1
    assert feedback_row is not None
    assert feedback_row.action_taken == "alert"
    assert feedback_row.detection_kind == "direct"
    assert feedback_row.analysis_backend == "endpoint_rule_prefilter"


@pytest.mark.asyncio
async def test_signed_endpoint_feedback_is_verified_and_persisted(
    ledger_client,
    evidence_client,
    auth_headers,
    entry_payload,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    db_session,
) -> None:
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir(parents=True, exist_ok=True)
    watched_file = watch_dir / "signed-simulant.txt"
    watched_file.write_text("benign direct-match simulant", encoding="utf-8")
    runtime_dir = tmp_path / "runtime"
    registry_path = generate_endpoint_material(runtime_dir, endpoint_id="endpoint-a")

    from avchain.utils.helpers import compute_sha256

    digest = compute_sha256(watched_file.read_bytes())
    direct_payload = dict(entry_payload)
    direct_payload["observables"] = [digest]
    entry = await _create_entry(ledger_client, auth_headers, direct_payload)
    await _transition_entry(
        ledger_client,
        auth_headers,
        entry_id=entry["id"],
        from_state="suspected",
        to_state="confirmed",
        actor="consensus",
        notes="seed confirmed entry",
    )

    monkeypatch.setenv("ENDPOINT_SCAN_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_WATCH_DIR", watch_dir.as_posix())
    monkeypatch.setenv("REMEDIATION_ACTION", "alert")
    monkeypatch.setenv("ENDPOINT_SIGNING_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_ID", "endpoint-a")
    monkeypatch.setenv(
        "ENDPOINT_PRIVATE_KEY_PATH",
        str(runtime_dir / "keys" / "endpoint-a_key.pem"),
    )
    monkeypatch.setenv("ENDPOINT_REGISTRY_PATH", str(registry_path))
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    reset_endpoint_registry_cache()
    worker = EndpointAgentWorker(
        ledger_client=ledger_client,
        evidence_client=evidence_client,
    )

    generated = await worker.run_once(events=[])
    feedback_row = (
        db_session.query(EntryFeedback).order_by(EntryFeedback.timestamp.desc()).first()
    )

    assert generated == 1
    assert feedback_row is not None
    assert feedback_row.endpoint_id == "endpoint-a"
    assert feedback_row.endpoint_signature_valid is True


@pytest.mark.asyncio
async def test_disabled_endpoint_registry_record_marks_signature_invalid(
    ledger_client,
    evidence_client,
    auth_headers,
    entry_payload,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    db_session,
) -> None:
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir(parents=True, exist_ok=True)
    watched_file = watch_dir / "signed-simulant-disabled.txt"
    watched_file.write_text("benign direct-match simulant", encoding="utf-8")
    runtime_dir = tmp_path / "runtime"
    registry_path = generate_endpoint_material(
        runtime_dir,
        endpoint_id="endpoint-disabled",
    )
    registry_file = Path(registry_path)
    registry_file.write_text(
        registry_file.read_text(encoding="utf-8").replace(
            "enabled: true",
            "enabled: false",
        ),
        encoding="utf-8",
    )

    from avchain.utils.helpers import compute_sha256

    digest = compute_sha256(watched_file.read_bytes())
    direct_payload = dict(entry_payload)
    direct_payload["observables"] = [digest]
    entry = await _create_entry(ledger_client, auth_headers, direct_payload)
    await _transition_entry(
        ledger_client,
        auth_headers,
        entry_id=entry["id"],
        from_state="suspected",
        to_state="confirmed",
        actor="consensus",
        notes="seed confirmed entry",
    )

    monkeypatch.setenv("ENDPOINT_SCAN_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_WATCH_DIR", watch_dir.as_posix())
    monkeypatch.setenv("REMEDIATION_ACTION", "alert")
    monkeypatch.setenv("ENDPOINT_SIGNING_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_ID", "endpoint-disabled")
    monkeypatch.setenv(
        "ENDPOINT_PRIVATE_KEY_PATH",
        str(runtime_dir / "keys" / "endpoint-disabled_key.pem"),
    )
    monkeypatch.setenv("ENDPOINT_REGISTRY_PATH", str(registry_path))
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    reset_endpoint_registry_cache()
    worker = EndpointAgentWorker(
        ledger_client=ledger_client,
        evidence_client=evidence_client,
    )

    with pytest.raises(httpx.HTTPStatusError):
        await worker.run_once(events=[])

    feedback_row = (
        db_session.query(EntryFeedback).order_by(EntryFeedback.timestamp.desc()).first()
    )

    assert feedback_row is None or feedback_row.endpoint_id != "endpoint-disabled"


@pytest.mark.asyncio
async def test_trust_endpoint_registry_surfaces_metadata(
    storage,
    auth_headers,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    registry_path = generate_endpoint_material(runtime_dir, endpoint_id="endpoint-b")
    registry_text = Path(registry_path).read_text(encoding="utf-8")
    Path(registry_path).write_text(
        registry_text.replace("trust_tier: standard", "trust_tier: elevated"),
        encoding="utf-8",
    )

    monkeypatch.setenv("ENDPOINT_REGISTRY_PATH", str(registry_path))
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    reset_endpoint_registry_cache()
    app = create_ledger_app(storage=storage)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://ledger",
    ) as client:
        list_response = await client.get(
            "/trust/endpoints",
            headers=auth_headers("ledger"),
        )
        detail_response = await client.get(
            "/trust/endpoints/endpoint-b",
            headers=auth_headers("ledger"),
        )

    assert list_response.status_code == 200
    assert list_response.json()[0]["trust_tier"] == "elevated"
    assert detail_response.status_code == 200
    assert detail_response.json()["enabled"] is True


@pytest.mark.asyncio
async def test_health_endpoints_report_ok(
    ledger_client,
    evidence_client,
    consensus_client,
    coverage_client,
    auth_headers,
) -> None:
    for client, service_name in (
        (ledger_client, "ledger"),
        (evidence_client, "evidence"),
        (consensus_client, "consensus"),
        (coverage_client, "coverage"),
    ):
        response = await client.get("/health", headers=auth_headers(service_name))
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_runtime_status_endpoints_expose_background_worker_values(
    ledger_client,
    auth_headers,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    heartbeat = datetime.now(UTC).isoformat()
    monkeypatch.setattr(
        "avchain.ledger.service.list_status_payloads",
        lambda freshness_seconds=60.0: [
            {
                "name": "validator1",
                "worker": "validator",
                "analysis_backend": "llm_lmstudio",
                "llm_model": "validator-audit-model",
                "fresh": True,
                "heartbeat_age_seconds": 0.5,
                "last_heartbeat": heartbeat,
            },
            {
                "name": "agent",
                "worker": "agent",
                "analysis_backend": "endpoint_rule_prefilter",
                "fresh": True,
                "heartbeat_age_seconds": 1.0,
                "last_heartbeat": heartbeat,
            },
        ],
    )
    monkeypatch.setattr(
        "avchain.ledger.service.read_status",
        lambda name: (
            {
                "worker": "validator" if name == "validator1" else "agent",
                "last_heartbeat": heartbeat,
            }
            if name in {"validator1", "agent"}
            else None
        ),
    )

    runtime_response = await ledger_client.get(
        "/runtime/status",
        headers=auth_headers("ledger"),
    )
    assert runtime_response.status_code == 200
    assert runtime_response.json()[0]["name"] == "validator1"

    detail_response = await ledger_client.get(
        "/runtime/status/validator1",
        headers=auth_headers("ledger"),
    )
    assert detail_response.status_code == 200
    assert detail_response.json()["worker"] == "validator"

    missing_response = await ledger_client.get(
        "/runtime/status/missing",
        headers=auth_headers("ledger"),
    )
    assert missing_response.status_code == 404
