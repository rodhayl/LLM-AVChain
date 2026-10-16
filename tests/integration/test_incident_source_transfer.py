"""Verify retrieved source decisions reach consumers; no real inference."""

from __future__ import annotations

import json

import pytest

from avchain.incident.models import Incident, RemediationPackage, TriageResult
from avchain.incident.triage import IncidentTriage, eligible_bindings
from avchain.scripts.run_incident_demo import run_lab


@pytest.mark.asyncio
async def test_source_observation_and_decision_reach_b_and_benign(
    test_environment, tmp_path
):
    calls = []

    class Model:
        async def analyze_incident(self, evidence):
            body = json.loads(evidence)
            calls.append(body)
            if len(calls) == 1:
                assert "knowledge_evidence" not in body
            else:
                contexts = body["knowledge_evidence"]
                assert len(contexts) == 1
                source = contexts[0]
                assert (
                    source["source_case_digest"]
                    in body["knowledge"]["evidence_digests"]
                )
                assert source["source_analysis"]["backend"] == "test_double"
                assert source["source_analysis"]["verdict"] == "suspicious"
                assert source["source_analysis"]["actions"]
                assert all("artifact_id" not in a for a in source["source_artifacts"])
                assert "read_text" in json.dumps(source["source_artifacts"])
                assert "PRIVATE_PROSE" not in json.dumps(source)
            incident = Incident.model_validate(body["incident"])
            package = RemediationPackage.model_validate(body["knowledge"])
            actions = eligible_bindings(incident, package)
            return TriageResult(
                verdict="suspicious" if actions else "benign",
                evidence_ids=[a.artifact_id for a in actions],
                actions=actions,
                explanation="PRIVATE_PROSE",
                inferences=["PRIVATE_PROSE"],
            )

    report = await run_lab(
        tmp_path, IncidentTriage(Model(), test_double=True), replay=False
    )
    assert len(calls) == 4
    assert calls[1]["knowledge_evidence"] == calls[2]["knowledge_evidence"]
    assert calls[2]["knowledge_evidence"] == calls[3]["knowledge_evidence"]
    assert report["nodes"]["benign"]["unchanged"] is True
    for name in ("node_a", "node_b", "benign"):
        assert (
            report["nodes"][name]["analysis"]["input_digest"]
            == report["rule_comparison"][name]["input_digest"]
        )
