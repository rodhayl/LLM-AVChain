from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from avchain.agent.worker import EndpointAgentWorker
from avchain.llm.schemas import EndpointClassificationOutput, ValidatorAnalysisOutput
from avchain.models.enums import LifecycleState, ProposalAction
from avchain.models.schemas import ThreatEntryCreate
from avchain.utils.helpers import compute_sha256
from avchain.validator.heuristics import LMStudioAnalysisStrategy
from avchain.validator.worker import ValidatorWorker


class FakeEndpointLLMClient:
    async def classify_endpoint_artifact(
        self,
        *,
        matched_observables: list[str],
        artifact_summary: str,
    ) -> EndpointClassificationOutput:
        _ = artifact_summary
        return EndpointClassificationOutput(
            verdict="malicious_simulant",
            severity="high",
            recommended_action="simulate_quarantine",
            explanation=f"Matched contextual indicators: {matched_observables}",
            confidence=0.88,
            behavior_tags=matched_observables,
        )


class FakeValidatorLLMClient:
    async def analyze_validator_evidence(
        self,
        *,
        observables: list[str],
        evidence_summaries: list[str],
    ) -> ValidatorAnalysisOutput:
        _ = observables, evidence_summaries
        return ValidatorAnalysisOutput(
            action=ProposalAction.PROMOTE,
            confidence=0.84,
            reasoning_summary="LM Studio local model would promote this entry",
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


async def _confirm_entry_with_lmstudio_validators(
    *,
    validator_key_paths,
    ledger_client,
    evidence_client,
    consensus_client,
) -> None:
    validator_one = ValidatorWorker(
        validator_id="validator1",
        private_key_path=validator_key_paths["validator1"],
        strategy=LMStudioAnalysisStrategy(client=FakeValidatorLLMClient()),
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        consensus_client=consensus_client,
    )
    validator_two = ValidatorWorker(
        validator_id="validator2",
        private_key_path=validator_key_paths["validator2"],
        strategy=LMStudioAnalysisStrategy(client=FakeValidatorLLMClient()),
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        consensus_client=consensus_client,
    )
    await validator_one.run_once()
    await validator_two.run_once()


@pytest.mark.asyncio
async def test_validator_worker_supports_lmstudio_strategy(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    validator_key_paths,
) -> None:
    payload = ThreatEntryCreate(
        observables=["lmstudio-ioc-a"],
        evidence=[{"content_type": "application/json", "data": {"signal": "x"}}],
        tlp_label="TLP:CLEAR",
    ).model_dump(mode="json")
    await _create_entry(ledger_client, auth_headers, payload)

    worker = ValidatorWorker(
        validator_id="validator1",
        private_key_path=validator_key_paths["validator1"],
        strategy=LMStudioAnalysisStrategy(client=FakeValidatorLLMClient()),
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        consensus_client=consensus_client,
    )

    processed = await worker.run_once()
    entries = await worker.poll_entries(LifecycleState.SUSPECTED)

    assert processed == 1
    assert worker.proposals_submitted == 1
    assert len(entries) == 1


@pytest.mark.asyncio
async def test_endpoint_worker_detects_direct_simulant_from_ledger(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    simulant_path = (
        Path("tests") / "fixtures" / "threat_simulants" / "eicar_avchain_001.txt"
    )
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir(parents=True, exist_ok=True)
    watched_file = watch_dir / simulant_path.name
    watched_file.write_bytes(simulant_path.read_bytes())
    quarantine_dir = tmp_path / "quarantine"

    digest = compute_sha256(watched_file.read_bytes())
    direct_payload = dict(entry_payload)
    direct_payload["observables"] = [digest]
    created_entry = await _create_entry(ledger_client, auth_headers, direct_payload)

    await _confirm_entry_with_lmstudio_validators(
        validator_key_paths=validator_key_paths,
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        consensus_client=consensus_client,
    )

    monkeypatch.setenv("ENDPOINT_SCAN_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_WATCH_DIR", watch_dir.as_posix())
    monkeypatch.setenv("ENDPOINT_QUARANTINE_DIR", quarantine_dir.as_posix())
    monkeypatch.setenv("REMEDIATION_ACTION", "simulate_quarantine")
    monkeypatch.setenv("TELEMETRY_RATE", "1")
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    worker = EndpointAgentWorker(
        ledger_client=ledger_client,
        evidence_client=evidence_client,
    )

    generated = await worker.run_once(events=[])

    assert generated == 1
    assert worker.artifact_detections == 1
    assert worker.last_matched_entry_id == created_entry["id"]
    assert (quarantine_dir / watched_file.name).exists()


@pytest.mark.asyncio
async def test_endpoint_worker_detects_contextual_package_simulant_with_llm(
    ledger_client,
    evidence_client,
    consensus_client,
    auth_headers,
    entry_payload,
    validator_key_paths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_dir = Path("tests") / "fixtures" / "threat_simulants" / "pkg_dropper_sim_001"
    watch_dir = tmp_path / "watch"
    copied_dir = watch_dir / source_dir.name
    shutil.copytree(source_dir, copied_dir)
    quarantine_dir = tmp_path / "quarantine"

    contextual_payload = dict(entry_payload)
    contextual_payload["observables"] = [
        "package:pkg-dropper-sim-001",
        "behavior:postinstall",
        "behavior:powershell-download",
    ]
    created_entry = await _create_entry(ledger_client, auth_headers, contextual_payload)

    await _confirm_entry_with_lmstudio_validators(
        validator_key_paths=validator_key_paths,
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        consensus_client=consensus_client,
    )

    monkeypatch.setenv("ENDPOINT_SCAN_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_WATCH_DIR", watch_dir.as_posix())
    monkeypatch.setenv("ENDPOINT_QUARANTINE_DIR", quarantine_dir.as_posix())
    monkeypatch.setenv("REMEDIATION_ACTION", "simulate_quarantine")
    monkeypatch.setenv("TELEMETRY_RATE", "1")
    from avchain.config.settings import reset_settings_cache

    reset_settings_cache()
    worker = EndpointAgentWorker(
        ledger_client=ledger_client,
        evidence_client=evidence_client,
        llm_client=FakeEndpointLLMClient(),
    )

    generated = await worker.run_once(events=[])

    assert generated == 1
    assert worker.artifact_detections == 1
    assert worker.last_matched_entry_id == created_entry["id"]
    assert (quarantine_dir / "package.json").exists() or (
        quarantine_dir / "install.js"
    ).exists()
