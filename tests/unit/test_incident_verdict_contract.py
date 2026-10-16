"""Prompt and guardrail contracts only; these doubles do not prove model accuracy."""

from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest

from avchain.incident.collector import IncidentCollector
from avchain.incident.executor import LocalApproval, ScopedExecutor, bindings_digest
from avchain.incident.knowledge import package_digest
from avchain.incident.lab import create_lab_fixture, draft_lab_package
from avchain.incident.models import ActionBinding, TriageResult
from avchain.incident.triage import (
    PROMPT,
    IncidentTriage,
    LocalIncidentModel,
    eligible_bindings,
    validate_triage,
)
from avchain.llm.providers.lmstudio import LMStudioClient


def test_prompt_defines_behavior_verdict_without_malice_or_label_shortcuts():
    assert "Prompt version: incident-v4." in PROMPT
    assert (
        "suspicious: evidence supports response-relevant behavior "
        "outside its permission" in PROMPT
    )
    assert (
        "benign: evidence supports ordinary or explicitly permitted behavior" in PROMPT
    )
    assert "uncertain: evidence is incomplete, conflicting or insufficient" in PROMPT
    assert "safe lab is distinct from transfer permission" in PROMPT
    assert "Tags constrain eligibility, not need" in PROMPT
    assert "benign or uncertain verdict must have no actions" in PROMPT
    for forbidden in ("node_a", "node_b", "setup_check.py", "install_check.py"):
        assert forbidden not in PROMPT


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "variant,benign", [(False, False), (True, False), (False, True)]
)
async def test_wire_contract_and_prompt_provenance_are_identical_for_all_cases(
    tmp_path, variant, benign
):
    root = tmp_path / "project"
    create_lab_fixture(root, variant=variant, benign=benign)
    incident = IncidentCollector(root).collect()
    package = draft_lab_package(uuid4(), ["a" * 64])
    calls = []
    # Always abstain, even where eligible bindings exist: no automatic correction.
    response = TriageResult(
        verdict="benign", explanation="Test double", evidence_ids=[]
    )

    def handler(request):
        calls.append(request)
        body = json.loads(request.content)
        assert body["messages"][0] == {"role": "system", "content": PROMPT}
        payload = json.loads(body["messages"][1]["content"])
        assert payload == {
            "incident": incident.model_dump(mode="json"),
            "knowledge": package.model_dump(mode="json"),
        }
        assert body["max_tokens"] == 3072
        assert body["temperature"] == 0
        assert (
            body["response_format"]["json_schema"]["schema"]
            == TriageResult.model_json_schema()
        )
        assert "reasoning_effort" not in body
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": response.model_dump_json()},
                    }
                ]
            },
        )

    model = LocalIncidentModel(
        LMStudioClient(
            endpoint_model="contract-test",
            max_retries=0,
            timeout_seconds=300,
            transport=httpx.MockTransport(handler),
        ),
        max_tokens=3072,
    )
    record = await IncidentTriage(model, test_double=True).analyze(incident, package)
    assert record.prompt_version == "incident-v4"
    assert record.backend == "test_double"
    assert record.output == response
    assert len(calls) == 1
    assert model.responses_received == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", ["benign", "uncertain"])
async def test_eligible_variant_abstention_remains_blocked(tmp_path, verdict):
    from datetime import UTC, datetime, timedelta

    from avchain.utils.helpers import compute_sha256

    root = tmp_path / "variant"
    create_lab_fixture(root, variant=True)
    collector = IncidentCollector(root)
    incident = collector.collect()
    package = draft_lab_package(uuid4(), ["a" * 64])
    assert len(eligible_bindings(incident, package)) == 2
    result = TriageResult(verdict=verdict, explanation="Abstention", evidence_ids=[])

    class Model:
        async def analyze_incident(self, evidence):
            return result

    record = await IncidentTriage(Model(), test_double=True).analyze(incident, package)
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    executor = ScopedExecutor(root, tmp_path / "recovery")
    approval = LocalApproval(
        incident.incident_id,
        package_digest(package),
        bindings_digest(record),
        compute_sha256(str(root.resolve()).encode()),
        datetime.now(UTC) + timedelta(minutes=1),
    )
    receipt = executor.apply(incident, package, record, collector.paths, approval)
    assert receipt.status == "blocked"
    assert receipt.operations == []
    assert executor.last_run_id is None
    assert before == {p.name: p.read_bytes() for p in root.iterdir()}
    with pytest.raises(ValueError, match="Non-suspicious"):
        validate_triage(
            result.model_copy(update={"actions": eligible_bindings(incident, package)}),
            incident,
            package,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["target", "read", "egress", "incomplete"])
async def test_labelled_simulation_and_package_never_supply_missing_behavior(
    tmp_path, missing
):
    root = tmp_path / "ordinary"
    create_lab_fixture(root)
    # Simulation provenance/catalog presence cannot supply a missing chain link.
    script = root / "install_check.py"
    if missing == "target":
        manifest = json.loads((root / "package.json").read_text())
        manifest["scripts"]["postinstall"] = "python3 absent.py"
        (root / "package.json").write_text(json.dumps(manifest))
    elif missing == "read":
        script.write_text("# simulation\n# 127.0.0.1 request\nprint('ordinary')\n")
    elif missing == "egress":
        script.write_text(
            "# simulation\n# AVCHAIN_CANARY read_text\nprint('ordinary')\n"
        )
    incident = IncidentCollector(root).collect()
    if missing == "incomplete":
        incident = incident.model_copy(update={"limitations": ["file_limit_reached"]})
    package = draft_lab_package(uuid4(), ["a" * 64])
    assert eligible_bindings(incident, package) == []
    record = await IncidentTriage().analyze(incident, package)
    assert record.output.actions == []
    invented = TriageResult(
        verdict="suspicious",
        explanation="Fixture label is not proof",
        evidence_ids=[incident.artifacts[0].artifact_id],
        actions=[
            ActionBinding(
                action_id="quarantine-hook",
                artifact_id=incident.artifacts[0].artifact_id,
            )
        ],
    )
    with pytest.raises(ValueError, match="Ungrounded"):
        validate_triage(invented, incident, package)


def test_legacy_record_keeps_v1_default():
    from avchain.incident.models import AnalysisRecord

    record = AnalysisRecord.model_validate(
        {
            "backend": "local_llm",
            "input_digest": "a" * 64,
            "output": {
                "verdict": "benign",
                "explanation": "Historic",
                "evidence_ids": [],
            },
        }
    )
    assert record.prompt_version == "incident-v1"


@pytest.mark.asyncio
async def test_request_failure_retains_current_prompt_identity():
    from avchain.utils.helpers import compute_sha256

    def handler(request):
        return httpx.Response(
            200,
            json={"choices": [{"finish_reason": "length", "message": {"content": ""}}]},
        )

    model = LocalIncidentModel(
        LMStudioClient(
            endpoint_model="test-only",
            max_retries=0,
            transport=httpx.MockTransport(handler),
        )
    )
    with pytest.raises(RuntimeError):
        await model.analyze_incident("bounded synthetic evidence")
    assert model.request_diagnostics[0]["prompt_version"] == "incident-v4"
    assert model.request_diagnostics[0]["system_prompt_sha256"] == compute_sha256(
        PROMPT.encode()
    )
    assert model.request_diagnostics[0]["structured_output_validated"] is False
