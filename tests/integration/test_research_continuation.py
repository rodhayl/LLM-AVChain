import asyncio
import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from avchain.consensus.registry import ValidatorRegistry
from avchain.incident.executor import ScopedExecutor
from avchain.incident.knowledge import KnowledgeStore, verify_package
from avchain.incident.models import SignedPackage
from avchain.incident.triage import LocalIncidentModel
from avchain.scripts import run_research_continuation as continuation
from avchain.utils.helpers import compute_sha256

EVIDENCE = Path(__file__).resolve().parents[2] / continuation.EVIDENCE_PATH


def test_real_archived_identity_signatures_and_expiry(tmp_path):
    incident = continuation.verify_history(EVIDENCE)
    assert incident["ledger_final"]["id"] == str(continuation.ENTRY_ID)
    assert incident["package_digest"] == continuation.PACKAGE_DIGEST
    # Historical signature checks never change the live package-validity gate.
    with pytest.raises(ValueError, match="Package not currently valid"):
        verify_package(
            SignedPackage.model_validate(incident["package"]),
            ValidatorRegistry(tmp_path / "no-live-validator-registry"),
        )


async def test_historical_continuation_is_isolated_and_data_only(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("No model, socket, process or remediation in this demo")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(LocalIncidentModel, "analyze_incident", forbidden)
    monkeypatch.setattr(ScopedExecutor, "apply", forbidden)
    monkeypatch.setattr(ScopedExecutor, "restore", forbidden)
    monkeypatch.setattr(KnowledgeStore, "publish", forbidden)
    monkeypatch.setattr(KnowledgeStore, "latest", forbidden)
    monkeypatch.setenv("LLM_PROVIDER", "lmstudio")
    monkeypatch.setenv("ENDPOINT_SCAN_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_NATIVE_SNAPSHOT_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_SIGNING_ENABLED", "true")
    sentinel = tmp_path / "existing.db"
    sentinel.write_bytes(b"Existing user data must remain untouched")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{sentinel}")
    before = {
        name: (EVIDENCE / name).read_bytes() for name in continuation.ARCHIVE_SHA256
    }
    databases = []
    original_create = continuation.create_engine_from_url

    def track_database(url):
        databases.append(Path(url.removeprefix("sqlite:///")))
        return original_create(url)

    monkeypatch.setattr(continuation, "create_engine_from_url", track_database)
    report = await continuation.run_demo(EVIDENCE)
    assert report["status"] == "PASS"
    assert all(report["checks"].values())
    assert report["target_entry_id"] == str(continuation.ENTRY_ID)
    assert report["package_digest"] == continuation.PACKAGE_DIGEST
    assert report["historical_import_simulation"] is True
    assert report["historical_signatures_verified"] == 2
    assert report["historical_evidence_url"] is None
    assert report["historical_evidence_commit"] == continuation.EVIDENCE_COMMIT
    assert report["historical_file_sha256"] == continuation.ORIGINAL_ARCHIVE_SHA256
    assert report["public_evidence_file_sha256"] == continuation.ARCHIVE_SHA256
    assert report["report_sanitization"] == {
        "kind": "privacy-preserving-public-derivative",
        "original_report_sha256": continuation.ORIGINAL_ARCHIVE_SHA256["REPORT.md"],
        "public_report_sha256": continuation.ARCHIVE_SHA256["REPORT.md"],
        "signed_incident_bytes_unchanged": True,
        "verification_bytes_unchanged": True,
        "path_aliases_are_synthetic": True,
    }
    assert report["historical_package_expired_at_run"] is True
    assert report["fresh_live_end_to_end"] is False
    assert report["package_execution_authorized"] is False
    assert report["fresh_model_calls"] == report["fresh_remediation_executions"] == 0
    assert report["coverage_source"] == "SIMULATED"
    assert report["real_vendor_integration"] is False
    assert report["events_stored"] == 2
    assert report["covered"] == report["replay"]
    assert report["baseline"] == report["reactivated"] == report["old_event_replay"]
    assert len(report["baseline"]) == 2
    for event in report["events"]:
        assert event["evidence"]["entry_id"] == str(continuation.ENTRY_ID)
        assert (
            compute_sha256(continuation.canonicalize(event["evidence"]))
            == event["evidence_digest"]
        )
    assert databases and all(not path.exists() for path in databases)
    assert sentinel.read_bytes() == b"Existing user data must remain untouched"
    assert before == {name: (EVIDENCE / name).read_bytes() for name in before}


@pytest.mark.parametrize("filename", list(continuation.ARCHIVE_SHA256))
def test_archive_tampering_fails_closed(tmp_path, filename):
    shutil.copytree(EVIDENCE, tmp_path / "archive")
    target = tmp_path / "archive" / filename
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(ValueError, match="Historical archive hash mismatch"):
        asyncio.run(continuation.run_demo(tmp_path / "archive"))


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ("entry", "identity mismatch"),
        ("digest", "identity mismatch"),
        ("signature", "Invalid historical package signature"),
        ("source_case", "Historical signed source links disagree"),
    ],
)
def test_semantic_provenance_checks_also_reject_tampering(
    tmp_path, monkeypatch, change, error
):
    shutil.copytree(EVIDENCE, tmp_path / "archive")
    path = tmp_path / "archive" / "incident-llm.json"
    incident = json.loads(path.read_bytes())
    if change == "entry":
        incident["ledger_final"]["id"] = "00000000-0000-0000-0000-000000000000"
    elif change == "digest":
        incident["package_digest"] = "0" * 64
    elif change == "signature":
        incident["package"]["approvals"][0]["signature"] = "invalid"
    else:
        incident["source_case"]["analysis"]["output"]["verdict"] = "benign"
    path.write_text(json.dumps(incident), encoding="utf-8")
    # Unit-test the secondary validators independently of the archive hash gate.
    # Production exposes no override for its pinned archive hashes.
    monkeypatch.setitem(
        continuation.ARCHIVE_SHA256,
        "incident-llm.json",
        compute_sha256(path.read_bytes()),
    )
    with pytest.raises(ValueError, match=error):
        continuation.verify_history(tmp_path / "archive")


def test_command_writes_report_without_overwriting_input(monkeypatch, tmp_path):
    output = tmp_path / "research.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["research", "--evidence-dir", str(EVIDENCE), "--output", str(output)],
    )
    assert continuation.main() == 0
    assert json.loads(output.read_bytes())["status"] == "PASS"
    original = (EVIDENCE / "incident-llm.json").read_bytes()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "research",
            "--evidence-dir",
            str(EVIDENCE),
            "--output",
            str(EVIDENCE / "incident-llm.json"),
        ],
    )
    with pytest.raises(SystemExit) as error:
        continuation.main()
    assert error.value.code == 2
    assert (EVIDENCE / "incident-llm.json").read_bytes() == original


def test_public_derivative_preserves_original_signed_evidence():
    assert (
        continuation.ARCHIVE_SHA256["REPORT.md"]
        != (continuation.ORIGINAL_ARCHIVE_SHA256["REPORT.md"])
    )
    for name in ("incident-llm.json", "verification.json"):
        assert (
            compute_sha256((EVIDENCE / name).read_bytes())
            == (continuation.ORIGINAL_ARCHIVE_SHA256[name])
        )
        assert (
            continuation.ARCHIVE_SHA256[name]
            == (continuation.ORIGINAL_ARCHIVE_SHA256[name])
        )
    report = (EVIDENCE / "REPORT.md").read_text(encoding="utf-8")
    assert "Public privacy-preserving derivative" in report
    assert "not byte-identical to the original" in report
    assert continuation.ORIGINAL_ARCHIVE_SHA256["REPORT.md"] in report
    assert continuation.HISTORICAL_SOURCE_SHA in report
    assert "https://github.com/rodhayl/LLM-AVChain/commit/" not in report


def test_public_supporting_paths_are_explicit_synthetic_aliases():
    preflight = json.loads((EVIDENCE / "preflight.json").read_bytes())
    execution = json.loads((EVIDENCE / "execution.json").read_bytes())
    expected_interpreter = "../dependency-env-1/.venv/Scripts/python.exe"
    assert preflight["sys_executable"] == expected_interpreter
    assert execution["interpreter"] == expected_interpreter
    assert execution["pythonpath"] == [
        "checkout/src",
        "../dependency-env-1/.venv/Lib/site-packages",
        "../dependency-env-2/.venv/Lib/site-packages",
    ]
    assert preflight["sys_executable_resolved_match"] is True
    assert execution["tested_sha"] == continuation.HISTORICAL_SOURCE_SHA
    assert execution["exit_code"] == 0
