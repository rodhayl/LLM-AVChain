from __future__ import annotations

import json

import pytest

from avchain.incident.knowledge import package_digest
from avchain.incident.models import RemediationPackage, TriageResult
from avchain.incident.triage import IncidentTriage
from avchain.scripts.run_incident_demo import LabProgress, run_lab
from avchain.utils.helpers import canonical_json_bytes, compute_sha256


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["abstention", "transport"])
async def test_exact_unsigned_draft_is_checkpointed_before_source_request(
    test_environment, tmp_path, failure
):
    progress = LabProgress(tmp_path / "checkpoint.json")
    calls = []

    class Model:
        async def analyze_incident(self, evidence):
            body = json.loads(evidence)
            calls.append(body)
            checkpoint = json.loads(progress.output.read_text())
            assert checkpoint["stages"]["source.analysis"] == "RUNNING"
            assert checkpoint["source_knowledge"] == body["knowledge"]
            assert checkpoint["source_knowledge_status"] == "unsigned_draft"
            assert checkpoint["source_knowledge_digest"] == package_digest(
                RemediationPackage.model_validate(body["knowledge"])
            )
            assert "package" not in checkpoint
            assert "source_case" not in checkpoint
            if failure == "transport":
                raise ValueError("PRIVATE_UNRETAINED_TRANSPORT_DETAIL")
            return TriageResult(
                verdict="benign",
                explanation="PRIVATE_UNRETAINED_PROSE",
                evidence_ids=[],
            )

    with pytest.raises(ValueError):
        await run_lab(
            tmp_path,
            IncidentTriage(Model(), test_double=True),
            replay=False,
            progress=progress,
        )
    saved = json.loads(progress.output.read_text())
    assert len(calls) == 1
    assert saved["stages"]["source.analysis"] == "FAIL"
    assert saved["stages"]["package.publication"] == "NOT_RUN"
    assert saved["source_knowledge"] == calls[0]["knowledge"]
    assert "PRIVATE_UNRETAINED" not in progress.output.read_text()
    assert str(tmp_path) not in progress.output.read_text()
    # Only excerpts of exact known owned fixtures are needed to reconstruct the
    # original input; dynamic entry IDs and validity timestamps are now retained.
    incident = saved["source_incident"]
    files = {
        compute_sha256(p.name.encode()): p.read_bytes()
        for p in (tmp_path / "node-a").iterdir()
    }
    for artifact in incident["artifacts"]:
        raw = files[artifact["artifact_id"]]
        assert compute_sha256(raw) == artifact["digest"]
        artifact["excerpt"] = raw.decode()[:8192]
    reconstructed = {"incident": incident, "knowledge": saved["source_knowledge"]}
    assert reconstructed == calls[0]
    if failure == "abstention":
        assert saved["failure"]["failed_checks"] == ["no_source_actions"]
        assert (
            compute_sha256(canonical_json_bytes(reconstructed))
            == saved["source_analysis"]["input_digest"]
        )
    else:
        assert "source_analysis" not in saved


@pytest.mark.asyncio
async def test_completed_report_keeps_draft_distinct_from_signed_package(
    test_environment, tmp_path
):
    report = await run_lab(tmp_path, IncidentTriage(), replay=False)
    assert report["source_knowledge_status"] == "unsigned_draft"
    assert report["source_knowledge"] == report["source_case"]["knowledge"]
    assert report["source_knowledge_digest"] == package_digest(
        RemediationPackage.model_validate(report["source_knowledge"])
    )
    assert report["source_knowledge_digest"] != report["package_digest"]
    assert len(report["source_knowledge"]["evidence_digests"]) == 1
    assert len(report["package"]["package"]["evidence_digests"]) == 2
