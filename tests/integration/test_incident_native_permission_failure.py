"""Replay retained native outputs through a double; never a real inference."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from avchain.incident.models import TriageResult
from avchain.incident.triage import IncidentTriage, LocalIncidentModel
from avchain.llm.providers.lmstudio import LMStudioClient
from avchain.scripts.run_incident_demo import LabProgress, run_lab


@pytest.mark.asyncio
async def test_all_four_native_outputs_still_fail_on_authorized_control(
    test_environment, tmp_path
):
    native = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "reports/incident_response_local_transfer_permission/incident-llm.json"
        ).read_text()
    )
    decisions = [native["source_analysis"]["output"]] + [
        native["nodes"][name]["analysis"]["output"]
        for name in ("node_a", "node_b", "benign")
    ]
    calls = []

    def handler(request):
        wire = json.loads(request.content)
        calls.append(wire)
        payload = json.loads(wire["messages"][1]["content"])
        if len(calls) == 4:
            assert len(payload["case_context"]["grants"]) == 1
            assert (
                payload["knowledge_evidence"][0]["source_case_context"]["grants"] == []
            )
        result = TriageResult(
            **decisions[len(calls) - 1], explanation="Retained decision replay"
        )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": result.model_dump_json()},
                    }
                ]
            },
        )

    model = LocalIncidentModel(
        LMStudioClient(
            endpoint_model="native-output-replay-only",
            max_retries=0,
            transport=httpx.MockTransport(handler),
        )
    )
    progress = LabProgress(tmp_path / "checkpoint.json")
    with pytest.raises(ValueError, match="Benign control received"):
        await run_lab(
            tmp_path, IncidentTriage(model, test_double=True), progress=progress
        )
    report = json.loads(progress.output.read_text())
    assert len(calls) == 4 and report["status"] == "blocked_or_inconclusive"
    for index, name in enumerate(("node_a", "node_b", "benign"), start=1):
        assert report["nodes"][name]["analysis"]["output"] == decisions[index]
        assert report["nodes"][name]["analysis"]["backend"] == "test_double"
    for name in ("node_a", "node_b"):
        assert report["nodes"][name]["after_egress"] == 0
        assert report["nodes"][name]["restored_egress"] == 1
        assert report["stages"][name + ".feedback"] == "PASS"
    control = report["nodes"]["benign"]
    assert control["analysis"]["output"]["verdict"] == "suspicious"
    assert control["analysis"]["prompt_version"] == "incident-v4"
    assert report["failure"]["failed_checks"] == ["authorized_control_actions_proposed"]
    assert report["stages"]["benign.unchanged"] == "FAIL"
    assert report["stages"]["final"] == "NOT_RUN"
    assert not {"receipt", "unchanged", "after_egress"} & set(control)
    assert native["failure"] == {
        "stage": "benign.unchanged"
    }  # Historical artifact unchanged.


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["bytes", "transfer"])
async def test_control_diagnostics_only_report_checks_actually_run(
    test_environment, tmp_path, monkeypatch, failure
):
    from avchain.scripts import run_incident_demo as demo

    original = demo.IncidentNode.investigate

    async def changed(self, *args, **kwargs):
        investigation = await original(self, *args, **kwargs)
        if failure == "bytes" and self.collector.root.name == "benign":
            (self.collector.root / "unexpected.txt").write_text(
                "Synthetic concurrent change"
            )
        return investigation

    monkeypatch.setattr(demo.IncidentNode, "investigate", changed)
    replay = demo.LoopbackCanary.replay_owned_fixture
    control_calls = 0

    def missing(self, root):
        nonlocal control_calls
        if root.name == "benign":
            control_calls += 1
            if failure == "transfer" and control_calls == 2:
                return 0
        return replay(self, root)

    monkeypatch.setattr(demo.LoopbackCanary, "replay_owned_fixture", missing)
    progress = LabProgress(tmp_path / "checkpoint.json")
    with pytest.raises(ValueError, match="Authorized control"):
        await run_lab(tmp_path, IncidentTriage(), progress=progress)
    report = json.loads(progress.output.read_text())
    control = report["nodes"]["benign"]
    assert report["failure"]["failed_checks"] == [
        "authorized_control_bytes_changed"
        if failure == "bytes"
        else "authorized_control_transfer_not_one"
    ]
    assert control["unchanged"] is (failure != "bytes")
    if failure == "bytes":
        assert control_calls == 1 and "after_egress" not in control
    else:
        assert control_calls == 2 and control["after_egress"] == 0
    assert "receipt" not in control and report["stages"]["final"] == "NOT_RUN"
