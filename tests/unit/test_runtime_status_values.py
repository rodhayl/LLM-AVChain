from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Queue
from threading import Event, Thread

import pytest

from avchain.agent.worker import EndpointAgentWorker
from avchain.config.settings import reset_settings_cache
from avchain.crypto.keys import generate_keypair, private_key_to_pem
from avchain.utils import runtime_status
from avchain.utils.runtime_status import (
    heartbeat_age_seconds,
    is_status_fresh,
    list_status_payloads,
    parse_heartbeat,
    write_status,
)
from avchain.validator.heuristics import LMStudioAnalysisStrategy
from avchain.validator.worker import ValidatorWorker


def test_status_publication_never_exposes_truncated_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "validator1.json"
    old = {"generation": "old"}
    target.write_text(json.dumps(old), encoding="utf-8")
    monkeypatch.setattr(runtime_status, "status_path", lambda _: target)
    original_replace = Path.replace
    original_write = Path.write_text
    original_open = Path.open
    requests: Queue[Event | None] = Queue()
    observations: list[bytes] = []
    failures: list[BaseException] = []

    def reader() -> None:
        while (ack := requests.get(timeout=5)) is not None:
            try:
                observations.append(target.read_bytes())
            except BaseException as exc:
                failures.append(exc)
            finally:
                ack.set()

    def observe() -> None:
        ack = Event()
        requests.put(ack)
        assert ack.wait(5), "reader failed to acknowledge requested read"

    attempts = 0

    def deny_first_replace(path: Path, destination: Path) -> Path:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            observe()
            raise PermissionError("controlled replacement denial")
        return original_replace(path, destination)

    def intercept_visible_write(path: Path, data: str, **kwargs: object) -> int:
        if path != target:
            return original_write(path, data, **kwargs)
        # The real open('w') truncates before the coordinated reader runs.
        with original_open(path, "w", encoding="utf-8") as handle:
            observe()
            return handle.write(data)

    monkeypatch.setattr(Path, "replace", deny_first_replace)
    monkeypatch.setattr(Path, "write_text", intercept_visible_write)
    thread = Thread(target=reader)
    thread.start()
    try:
        assert write_status("validator1", {"generation": "new"}) == target
        observe()
    finally:
        requests.put(None)
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert failures == []
    assert observations
    assert all(raw for raw in observations), observations
    assert all(json.loads(raw)["generation"] in {"old", "new"} for raw in observations)
    assert json.loads(observations[-1])["generation"] == "new"
    assert attempts == 2
    assert list(tmp_path.glob("*.tmp")) == []


@pytest.mark.parametrize("failure_stage", ["replace", "temporary-write"])
@pytest.mark.parametrize("existing", [False, True])
def test_status_exhaustion_preserves_last_valid_state_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_stage: str, existing: bool
) -> None:
    target = tmp_path / "validator1.json"
    old = b'{"generation":"old"}'
    if existing:
        target.write_bytes(old)
    monkeypatch.setattr(runtime_status, "status_path", lambda _: target)
    sleeps: list[float] = []
    monkeypatch.setattr(runtime_status.time, "sleep", sleeps.append)
    attempts = 0
    original_replace = Path.replace
    original_write = Path.write_text

    def fail_replace(path: Path, destination: Path) -> Path:
        nonlocal attempts
        attempts += 1
        raise PermissionError("persistent denial")

    def fail_write(path: Path, data: str, **kwargs: object) -> int:
        nonlocal attempts
        attempts += 1
        path.write_bytes(b"incomplete temporary")
        raise OSError("temporary write failed")

    if failure_stage == "replace":
        monkeypatch.setattr(Path, "replace", fail_replace)
    else:
        monkeypatch.setattr(Path, "write_text", fail_write)
    with pytest.raises(
        runtime_status.StatusPublicationError, match="after 5 attempts"
    ) as error:
        write_status("validator1", {"generation": "new"})
    assert isinstance(error.value.__cause__, OSError)
    assert attempts == 5
    assert sleeps == [0.05] * 4
    assert target.read_bytes() == old if existing else not target.exists()
    assert list(tmp_path.glob("*.tmp")) == []
    monkeypatch.setattr(Path, "replace", original_replace)
    monkeypatch.setattr(Path, "write_text", original_write)
    assert write_status("validator1", {"generation": "recovered"}) == target
    assert json.loads(target.read_bytes())["generation"] == "recovered"
    assert list(tmp_path.glob("*.tmp")) == []


@pytest.mark.parametrize("kind", ["agent", "validator"])
def test_workers_report_publication_failure_without_recursive_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    from avchain.agent import worker as agent_module
    from avchain.validator import worker as validator_module

    if kind == "agent":
        worker = EndpointAgentWorker(status_name=None)
        module = agent_module
    else:
        private_key, _ = generate_keypair()
        key = tmp_path / "key.pem"
        key.write_text(private_key_to_pem(private_key), encoding="utf-8")
        worker = ValidatorWorker("validator1", key, status_name=None)
        module = validator_module
    worker.status_name = kind
    target = tmp_path / "status.json"
    monkeypatch.setattr(runtime_status, "status_path", lambda _: target)
    calls = 0

    def unavailable(*args: object) -> Path:
        nonlocal calls
        calls += 1
        raise runtime_status.StatusPublicationError("controlled denial")

    monkeypatch.setattr(module, "write_status", unavailable)
    worker._record_error(RuntimeError("business failure"))
    assert calls == 1
    assert worker.last_error == "RuntimeError: business failure"
    assert worker.last_status_error == "StatusPublicationError: controlled denial"
    assert worker.last_status_error_at
    assert "status publication failed" in capsys.readouterr().err
    assert worker._write_status() is False
    assert calls == 2
    monkeypatch.setattr(module, "write_status", write_status)
    assert worker._write_status() is True
    assert worker.last_status_error is None
    assert worker.last_status_error_at is None
    payload = json.loads(target.read_bytes())
    assert payload["last_error"] == "RuntimeError: business failure"
    assert payload["last_status_error"] == ""


def test_runtime_status_helpers_compute_freshness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "VALIDATOR_REGISTRY_PATH",
        (tmp_path / "runtime" / "validators.yaml").as_posix(),
    )
    reset_settings_cache()

    write_status("agent", {"worker": "agent", "events_processed": 3})
    payload = next(
        item
        for item in list_status_payloads(freshness_seconds=30.0)
        if item["name"] == "agent"
    )

    assert payload["name"] == "agent"
    assert payload["fresh"] is True
    assert parse_heartbeat(payload) is not None
    assert heartbeat_age_seconds(payload) is not None
    assert is_status_fresh(payload, freshness_seconds=30.0) is True


def test_runtime_status_helpers_mark_stale_payloads() -> None:
    now = datetime.now(UTC)
    payload = {"last_heartbeat": (now - timedelta(seconds=61)).isoformat()}

    assert parse_heartbeat(payload) is not None
    assert heartbeat_age_seconds(payload, now=now) == pytest.approx(61.0, abs=0.5)
    assert is_status_fresh(payload, freshness_seconds=30.0, now=now) is False


class DummyValidatorLLMClient:
    async def analyze_validator_evidence(
        self,
        *,
        observables: list[str],
        evidence_summaries: list[str],
    ) -> object:
        _ = observables, evidence_summaries
        raise AssertionError("not used in this test")


def test_validator_status_exposes_backend_and_error_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key, _ = generate_keypair()
    key_path = tmp_path / "validator1_key.pem"
    key_path.write_text(private_key_to_pem(private_key), encoding="utf-8")
    monkeypatch.setenv("LLM_PROVIDER", "lmstudio")
    monkeypatch.setenv("LMSTUDIO_MODEL_VALIDATOR", "validator-audit-model")
    reset_settings_cache()

    worker = ValidatorWorker(
        validator_id="validator1",
        private_key_path=key_path,
        strategy=LMStudioAnalysisStrategy(client=DummyValidatorLLMClient()),
        status_name=None,
    )
    worker._record_error(RuntimeError("validator boom"))
    status = worker.status()

    assert status["worker"] == "validator"
    assert status["analysis_backend"] == "llm_lmstudio"
    assert status["llm_provider"] == "lmstudio"
    assert status["llm_model"] == "validator-audit-model"
    assert status["prompt_name"] == "validator_triage"
    assert status["prompt_version"] == "v1"
    assert status["poll_interval"] >= 1
    assert status["last_error"] == "RuntimeError: validator boom"
    assert status["last_error_at"]


def test_agent_status_exposes_runtime_values_and_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("LLM_PROVIDER", "lmstudio")
    monkeypatch.setenv("LMSTUDIO_MODEL_ENDPOINT", "endpoint-audit-model")
    monkeypatch.setenv("ENDPOINT_SCAN_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_WATCH_DIR", watch_dir.as_posix())
    monkeypatch.setenv("ENDPOINT_NATIVE_SNAPSHOT_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_PROCESS_EVENTS_PATH", "process.jsonl")
    monkeypatch.setenv("ENDPOINT_PACKAGE_EVENTS_PATH", "package.jsonl")
    monkeypatch.setenv("ENDPOINT_NETWORK_EVENTS_PATH", "network.jsonl")
    monkeypatch.setenv("REMEDIATION_ACTION", "alert")
    reset_settings_cache()

    worker = EndpointAgentWorker(status_name=None)
    worker._record_error(RuntimeError("agent boom"))
    status = worker.status()

    assert status["worker"] == "agent"
    assert status["endpoint_scan_enabled"] == 1
    assert status["native_snapshot_enabled"] == 1
    assert status["external_process_events"] == 1
    assert status["external_package_events"] == 1
    assert status["external_network_events"] == 1
    assert status["llm_enabled"] == 1
    assert status["analysis_backend"] == "endpoint_rule_prefilter"
    assert status["llm_provider"] == ""
    assert status["llm_model"] == "endpoint-audit-model"
    assert Path(str(status["endpoint_watch_dir"])) == watch_dir
    assert status["remediation_action"] == "alert"
    assert status["last_error"] == "RuntimeError: agent boom"
    assert status["last_error_at"]
