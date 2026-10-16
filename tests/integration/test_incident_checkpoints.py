from __future__ import annotations

import json

import pytest

from avchain.incident.models import TransferCaseContext, TriageResult
from avchain.incident.observations import matching_transfer_grant
from avchain.incident.triage import IncidentTriage
from avchain.scripts import run_incident_demo as demo


class NodeBAbstains:
    """A deterministic test double, never evidence of a real model run."""

    def __init__(self):
        self.calls = 0

    async def analyze_incident(self, evidence):
        from avchain.incident.models import Incident, RemediationPackage
        from avchain.incident.triage import eligible_bindings

        self.calls += 1
        body = json.loads(evidence)
        incident = Incident.model_validate(body["incident"])
        package = RemediationPackage.model_validate(body["knowledge"])
        actions = eligible_bindings(incident, package) if self.calls < 3 else []
        return TriageResult(
            verdict="suspicious" if actions else "uncertain",
            explanation="PRIVATE_MODEL_PROSE_DO_NOT_RETAIN",
            inferences=["PRIVATE_HYPOTHESIS_DO_NOT_RETAIN"],
            evidence_ids=[a.artifact_id for a in actions],
            actions=actions,
        )


def test_cli_retains_b_block_and_completed_a_receipts(tmp_path, monkeypatch):
    model = NodeBAbstains()
    triage = IncidentTriage(model, test_double=True)
    instances = iter([triage])
    # The comparison must still use the actual deterministic rules baseline.
    monkeypatch.setattr(
        demo, "IncidentTriage", lambda: next(instances, IncidentTriage())
    )
    output = tmp_path / "report.json"
    monkeypatch.setattr(
        "sys.argv", ["demo", "--mode", "rules", "--output", str(output)]
    )
    assert demo.main() == 2
    report = json.loads(output.read_text())
    assert "nodes" in report, "Failure discarded the partial node receipts"
    assert report["nodes"]["node_a"]["receipt"]["status"] == "applied"
    assert report["nodes"]["node_a"]["recovery"]["status"] == "rolled_back"
    assert report["nodes"]["node_b"]["receipt"]["status"] == "blocked"
    assert report["nodes"]["node_b"]["after_egress"] == 1
    assert report["stages"]["node_b.containment"] == "FAIL"
    assert report["stages"]["node_b.recovery"] == "NOT_RUN"
    assert report["stages"]["benign.investigation"] == "NOT_RUN"
    assert report["failure"]["failed_checks"] == [
        "receipt_not_applied",
        "canary_egress_not_zero",
    ]
    assert report["status"] == "blocked_or_inconclusive"
    assert report["fallback_used"] is False
    assert model.calls == 3
    assert "PRIVATE_MODEL_PROSE" not in output.read_text()
    assert "PRIVATE_HYPOTHESIS" not in output.read_text()
    assert str(tmp_path) not in output.read_text()


class SelectedActions:
    def __init__(self, selected):
        self.selected = selected
        self.calls = 0

    async def analyze_incident(self, evidence):
        from avchain.incident.models import Incident, RemediationPackage
        from avchain.incident.triage import eligible_bindings

        self.calls += 1
        body = json.loads(evidence)
        incident = Incident.model_validate(body["incident"])
        package = RemediationPackage.model_validate(body["knowledge"])
        eligible = eligible_bindings(incident, package)
        # This deterministic double compares the case grant explicitly.
        # Product model outputs are never filtered by this baseline helper.
        if (
            body.get("case_context") is not None
            and matching_transfer_grant(
                TransferCaseContext.model_validate(body["case_context"])
            )
            is True
        ):
            eligible = []
        actions = [
            binding
            for action in self.selected
            for binding in eligible
            if binding.action_id == action
        ]
        return TriageResult(
            verdict="suspicious" if actions else "uncertain",
            explanation="Deterministic eligible-action selection, not inference",
            evidence_ids=[binding.artifact_id for binding in actions],
            actions=actions,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "selected",
    [
        ["disable-hook"],
        ["quarantine-hook"],
        ["disable-hook", "quarantine-hook"],
        ["quarantine-hook", "disable-hook"],
    ],
)
async def test_each_eligible_subset_and_order_contains_both_variants(
    test_environment, tmp_path, selected
):
    from avchain.consensus.registry import get_registry
    from avchain.incident.knowledge import verify_package
    from avchain.incident.models import SignedPackage

    model = SelectedActions(selected)
    report = await demo.run_lab(tmp_path, IncidentTriage(model, test_double=True))
    assert report["mode"] == "test_double"
    assert report["real_model_executed"] is False
    assert model.calls == 4
    assert report["two_nodes_same_package"] is True
    verify_package(SignedPackage.model_validate(report["package"]), get_registry())
    for name in ("node_a", "node_b"):
        node = report["nodes"][name]
        assert (
            report["before_egress"][name],
            node["after_egress"],
            node["restored_egress"],
        ) == (1, 0, 1)
        assert node["receipt"]["status"] == "applied"
        assert node["recovery"]["status"] == "rolled_back"
        assert len(node["receipt"]["operations"]) == len(selected)
        assert [
            a["action_id"] for a in node["analysis"]["output"]["actions"]
        ] == selected
    assert report["nodes"]["benign"]["unchanged"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["egress", "postcheck", "replay_error", "recovery"])
async def test_b_failure_preserves_evidence_without_passing_gate(
    test_environment, tmp_path, monkeypatch, failure
):
    from avchain.incident.executor import ScopedExecutor

    output = tmp_path / "checkpoint.json"
    progress = demo.LabProgress(output)
    original_replay = demo.LoopbackCanary.replay_owned_fixture
    original_postcheck = ScopedExecutor._postcheck
    original_restore = ScopedExecutor.restore
    b_replays = 0

    def replay(self, root):
        nonlocal b_replays
        if root.name == "node-b":
            b_replays += 1
            if b_replays == 2:
                # The completed mutation receipt is durable before replay starts.
                saved = json.loads(output.read_text())
                assert saved["nodes"]["node_b"]["receipt"]["status"] in {
                    "applied",
                    "rolled_back",
                }
                assert saved["stages"]["node_b.containment"] == "RUNNING"
                if failure == "replay_error":
                    raise OSError("PRIVATE_PATH=/home/secret-user/project")
                if failure == "egress":
                    return 1
        return original_replay(self, root)

    def postcheck(self, rows):
        if self.root.name == "node-b" and failure == "postcheck":
            raise ValueError("PRIVATE_POSTCHECK_DETAIL")
        return original_postcheck(self, rows)

    def restore(self, run_id):
        if self.root.name == "node-b" and failure == "recovery":
            raise OSError("PRIVATE_RECOVERY_DETAIL")
        return original_restore(self, run_id)

    monkeypatch.setattr(demo.LoopbackCanary, "replay_owned_fixture", replay)
    monkeypatch.setattr(ScopedExecutor, "_postcheck", postcheck)
    monkeypatch.setattr(ScopedExecutor, "restore", restore)
    with pytest.raises((ValueError, OSError)):
        await demo.run_lab(tmp_path, IncidentTriage(), progress=progress)
    report = json.loads(output.read_text())
    assert report["status"] == "blocked_or_inconclusive"
    assert report["two_nodes_same_package"] is True
    assert report["nodes"]["node_a"]["recovery"]["status"] == "rolled_back"
    assert report["stages"]["node_a.feedback"] == "PASS"
    assert report["stages"]["benign.investigation"] == "NOT_RUN"
    assert "PRIVATE_" not in output.read_text()
    assert str(tmp_path) not in output.read_text()
    if failure == "egress":
        assert report["nodes"]["node_b"]["receipt"]["status"] == "applied"
        assert report["failure"]["failed_checks"] == ["canary_egress_not_zero"]
    if failure == "postcheck":
        assert report["nodes"]["node_b"]["receipt"]["status"] == "rolled_back"
        assert report["failure"]["failed_checks"] == [
            "receipt_not_applied",
            "canary_egress_not_zero",
        ]
    if failure == "replay_error":
        assert "after_egress" not in report["nodes"]["node_b"]
        assert report["failure"]["stage"] == "node_b.containment"
        assert report["error_type"] == "OSError"
    if failure == "recovery":
        assert report["stages"]["node_b.containment"] == "PASS"
        assert report["stages"]["node_b.recovery"] == "FAIL"
        assert report["stages"]["node_b.feedback"] == "NOT_RUN"
        assert report["nodes"]["node_b"]["after_egress"] == 0


@pytest.mark.asyncio
async def test_b_invalid_model_output_keeps_a_and_no_raw_exception(
    test_environment, tmp_path
):
    class InvalidB(SelectedActions):
        async def analyze_incident(self, evidence):
            if self.calls == 2:
                # Pydantic messages can quote rejected raw model text.
                return TriageResult.model_validate({"PRIVATE_MODEL_PAYLOAD": "invalid"})
            return await super().analyze_incident(evidence)

    progress = demo.LabProgress(tmp_path / "checkpoint.json")
    with pytest.raises(ValueError):
        await demo.run_lab(
            tmp_path,
            IncidentTriage(InvalidB(["disable-hook"]), test_double=True),
            progress=progress,
        )
    report = json.loads(progress.output.read_text())
    assert report["stages"]["node_b.investigation"] == "FAIL"
    assert report["stages"]["node_b.containment"] == "NOT_RUN"
    assert report["nodes"]["node_a"]["recovery"]["status"] == "rolled_back"
    assert report["nodes"]["node_b"] == {}
    assert "PRIVATE_MODEL_PAYLOAD" not in progress.output.read_text()


def test_receipt_checkpoint_does_not_export_recovery_paths():
    from avchain.incident.models import ExecutionReceipt

    receipt = ExecutionReceipt(
        status="rollback_incomplete",
        incident_id="test-id",
        package_digest="a" * 64,
        operations=[
            {
                "artifact_id": "b" * 64,
                "operation": "quarantine_file",
                "before": "c" * 64,
                "after": "absent",
                "relative": "PRIVATE_PATH",
                "backup": "PRIVATE_BACKUP",
            }
        ],
        explanation="PRIVATE_EXPLANATION",
    )
    result = demo.receipt_checkpoint(receipt)
    assert result["status"] == "rollback_incomplete"
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.asyncio
async def test_successful_checkpoint_is_terminal_and_no_replay_is_explicit(
    test_environment, tmp_path
):
    progress = demo.LabProgress(tmp_path / "checkpoint.json")
    result = await demo.run_lab(
        tmp_path, IncidentTriage(), replay=False, progress=progress
    )
    saved = json.loads(progress.output.read_text())
    assert saved["status"] == result["status"] == "passed"
    assert saved["stages"]["final"] == "PASS"
    assert saved["stages"]["baseline"] == "NOT_RUN"
    assert saved["before_egress"] == {"node_a": None, "node_b": None, "benign": None}


@pytest.mark.asyncio
async def test_bad_baseline_stops_before_model_analysis(
    test_environment, tmp_path, monkeypatch
):
    class NoEgressCanary:
        def replay_owned_fixture(self, root):
            return 0

        def close(self):
            pass

    monkeypatch.setattr(demo, "LoopbackCanary", NoEgressCanary)
    model = SelectedActions(["disable-hook"])
    progress = demo.LabProgress(tmp_path / "checkpoint.json")
    with pytest.raises(ValueError, match="baseline"):
        await demo.run_lab(
            tmp_path, IncidentTriage(model, test_double=True), progress=progress
        )
    saved = json.loads(progress.output.read_text())
    assert saved["stages"]["baseline"] == "FAIL"
    assert saved["stages"]["source.analysis"] == "NOT_RUN"
    assert saved["failure"]["failed_checks"] == ["baseline_egress"]
    assert model.calls == 0
