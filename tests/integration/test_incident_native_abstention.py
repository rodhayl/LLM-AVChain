"""Replay a retained decision through a transport double, never a real model."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from avchain.incident.models import Incident, RemediationPackage, TriageResult
from avchain.incident.triage import (
    IncidentTriage,
    LocalIncidentModel,
    eligible_bindings,
)
from avchain.llm.providers.lmstudio import LMStudioClient
from avchain.scripts.run_incident_demo import LabProgress, run_lab


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "evidence_dir",
    ["incident_response_local_checkpointed", "incident_response_local_verdict_v2"],
)
async def test_retained_native_b_benign_decision_is_not_overridden_by_retrieved_case(
    test_environment, tmp_path, evidence_dir
):
    native = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "reports"
            / evidence_dir
            / "incident-llm.json"
        ).read_text()
    )
    decision = native["nodes"]["node_b"]["analysis"]["output"]
    assert decision["verdict"] == "benign" and decision["actions"] == []
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        evidence = json.loads(body["messages"][1]["content"])
        incident = Incident.model_validate(evidence["incident"])
        package = RemediationPackage.model_validate(evidence["knowledge"])
        if len(calls) == 3:
            assert len(evidence["knowledge_evidence"]) == 1
            # Explanation was not retained. No invented model rationale is used.
            output = TriageResult(**decision, explanation="Retained decision replay")
        else:
            actions = eligible_bindings(incident, package)
            output = TriageResult(
                verdict="suspicious",
                explanation="Deterministic double",
                evidence_ids=[b.artifact_id for b in actions],
                actions=actions,
            )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": output.model_dump_json()},
                    }
                ]
            },
        )

    model = LocalIncidentModel(
        LMStudioClient(
            endpoint_model="test-only",
            max_retries=0,
            transport=httpx.MockTransport(handler),
        )
    )
    progress = LabProgress(tmp_path / "checkpoint.json")
    with pytest.raises(ValueError, match="Containment did not pass"):
        await run_lab(
            tmp_path, IncidentTriage(model, test_double=True), progress=progress
        )
    report = json.loads(progress.output.read_text())
    assert len(calls) == 3
    assert report["nodes"]["node_b"]["analysis"]["prompt_version"] == "incident-v4"
    assert report["nodes"]["node_b"]["analysis"]["backend"] == "test_double"
    assert report["nodes"]["node_b"]["analysis"]["output"] == decision
    assert report["nodes"]["node_b"]["receipt"]["status"] == "blocked"
    assert (
        report["nodes"]["node_b"]["source_evidence"]
        == report["nodes"]["node_a"]["source_evidence"]
    )
    assert report["nodes"]["node_b"]["after_egress"] == 1
    assert report["nodes"]["node_a"]["after_egress"] == 0
    assert report["nodes"]["node_a"]["restored_egress"] == 1
    assert report["stages"]["node_b.recovery"] == "NOT_RUN"
    assert report["stages"]["benign.investigation"] == "NOT_RUN"
