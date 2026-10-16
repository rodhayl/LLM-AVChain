"""Owned loopback observations + explicit grants; every model here is a double."""

from __future__ import annotations

import json

import pytest

from avchain.incident.models import (
    Incident,
    RemediationPackage,
    TransferCaseContext,
    TriageResult,
)
from avchain.incident.triage import IncidentTriage, eligible_bindings
from avchain.scripts.run_incident_demo import LabProgress, run_lab


class GrantComparisonDouble:
    def __init__(self):
        self.inputs = []

    async def analyze_incident(self, evidence):
        body = json.loads(evidence)
        self.inputs.append(body)
        result = await IncidentTriage().analyze(
            Incident.model_validate(body["incident"]),
            RemediationPackage.model_validate(body["knowledge"]),
            case_context=TransferCaseContext.model_validate(body["case_context"]),
            knowledge_evidence=body.get("knowledge_evidence"),
        )
        return result.output


@pytest.mark.asyncio
async def test_same_observed_behavior_differs_only_in_concrete_grant(
    test_environment, tmp_path
):
    model = GrantComparisonDouble()
    report = await run_lab(tmp_path, IncidentTriage(model, test_double=True))
    assert len(model.inputs) == 4
    assert report["before_egress"] == {"node_a": 1, "node_b": 1, "benign": 1}
    contexts = [body["case_context"] for body in model.inputs]
    assert all(c["grant_records_complete"] for c in contexts)
    assert [len(c["grants"]) for c in contexts] == [0, 0, 0, 1]
    assert len({c["lab_scope"] for c in contexts}) == 1
    assert (
        len({tuple(c["observation"]["received_payload_digests"]) for c in contexts})
        == 1
    )
    assert all(
        c["observation"]["source"] == "owned_receiver_during_verified_replay"
        for c in contexts
    )
    for context in contexts:
        keys = set(context) | set(context["observation"])
        assert not keys & {
            "verdict",
            "expected_verdict",
            "actions",
            "expected_actions",
            "unauthorized",
            "read_observed",
        }
    a, benign = report["nodes"]["node_a"], report["nodes"]["benign"]

    def artifact_bytes(node):
        return {
            x["artifact_id"]: (x["digest"], x["excerpt"])
            for x in node["incident"]["artifacts"]
        }

    assert artifact_bytes(a) == artifact_bytes(benign)
    assert a["after_egress"] == 0 and a["restored_egress"] == 1
    assert benign["unchanged"] is True and benign["after_egress"] == 1
    assert benign["analysis"]["output"]["actions"] == []
    assert report["source_case"]["case_context"] == contexts[0]
    shared = model.inputs[2]["knowledge_evidence"][0]["source_case_context"]
    assert "source_resource_artifact_id" in shared
    assert "resource_artifact_id" not in shared
    assert "source_actor_artifact_id" in shared["observation"]
    assert "actor_path_hash" not in shared["observation"]
    for name in ("node_a", "node_b", "benign"):
        assert (
            report["nodes"][name]["analysis"]["input_digest"]
            == report["rule_comparison"][name]["input_digest"]
        )


@pytest.mark.asyncio
async def test_observed_transfer_without_grant_does_not_force_source_actions(
    test_environment, tmp_path
):
    calls = []

    class Abstain:
        async def analyze_incident(self, evidence):
            body = json.loads(evidence)
            calls.append(body)
            assert body["case_context"]["observation"]["received_payload_digests"]
            assert body["case_context"]["grants"] == []
            return TriageResult(
                verdict="benign", explanation="Synthetic abstention", evidence_ids=[]
            )

    progress = LabProgress(tmp_path / "report.json")
    with pytest.raises(ValueError, match="no applicable actions"):
        await run_lab(
            tmp_path, IncidentTriage(Abstain(), test_double=True), progress=progress
        )
    report = json.loads(progress.output.read_text())
    assert len(calls) == 1
    assert report["failure"]["failed_checks"] == ["no_source_actions"]
    assert report["source_context"] == calls[0]["case_context"]
    from avchain.utils.helpers import canonical_json_bytes, compute_sha256

    assert report["source_analysis"]["input_digest"] == compute_sha256(
        canonical_json_bytes(calls[0])
    )
    assert report["source_knowledge_status"] == "unsigned_draft"
    assert report["stages"]["package.publication"] == "NOT_RUN"
    assert "package" not in report


@pytest.mark.asyncio
async def test_wrong_observation_digest_stops_before_any_model_call(
    test_environment, tmp_path, monkeypatch
):
    from avchain.scripts import run_incident_demo as demo

    original = demo.transfer_case

    def wrong(observation, **kwargs):
        context = original(observation, **kwargs)
        return context.model_copy(
            update={
                "observation": observation.model_copy(
                    update={"received_payload_digests": ["f" * 64]}
                )
            }
        )

    monkeypatch.setattr(demo, "transfer_case", wrong)
    model = GrantComparisonDouble()
    with pytest.raises(ValueError, match="Receiver evidence"):
        await run_lab(tmp_path, IncidentTriage(model, test_double=True))
    assert model.inputs == []


@pytest.mark.asyncio
async def test_model_actions_on_authorized_control_fail_instead_of_being_overridden(
    test_environment, tmp_path
):
    class FalsePositive(GrantComparisonDouble):
        async def analyze_incident(self, evidence):
            output = await super().analyze_incident(evidence)
            if len(self.inputs) == 4:
                body = self.inputs[-1]
                actions = eligible_bindings(
                    Incident.model_validate(body["incident"]),
                    RemediationPackage.model_validate(body["knowledge"]),
                )
                return TriageResult(
                    verdict="suspicious",
                    explanation="Synthetic false positive",
                    actions=actions,
                    evidence_ids=[a.artifact_id for a in actions],
                )
            return output

    model = FalsePositive()
    progress = LabProgress(tmp_path / "report.json")
    with pytest.raises(ValueError, match="Benign control received"):
        await run_lab(
            tmp_path, IncidentTriage(model, test_double=True), progress=progress
        )
    report = json.loads(progress.output.read_text())
    assert len(model.inputs) == 4
    assert report["stages"]["benign.unchanged"] == "FAIL"
    assert report["nodes"]["benign"]["analysis"]["output"]["actions"]
    assert "receipt" not in report["nodes"]["benign"]
    assert "unchanged" not in report["nodes"]["benign"]
    assert "after_egress" not in report["nodes"]["benign"]
    assert report["failure"]["failed_checks"] == ["authorized_control_actions_proposed"]


def test_marker_only_script_cannot_manufacture_a_receiver_observation(tmp_path):
    from avchain.incident.lab import create_lab_fixture
    from avchain.scripts.run_incident_demo import LoopbackCanary

    root = tmp_path / "marker-only"
    create_lab_fixture(root)
    (root / "install_check.py").write_text(
        '# AVCHAIN_CANARY read_text 127.0.0.1 request\nprint("ordinary build")\n'
    )
    receiver = LoopbackCanary()
    try:
        with pytest.raises(ValueError, match="Refusing modified"):
            receiver.replay_owned_fixture(root)
        assert receiver.hits == []
        assert receiver.last_transfer is None
    finally:
        receiver.close()
