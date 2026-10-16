from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest


def test_start_batch_uses_venv_interpreter_without_activation() -> None:
    script = Path("start.bat").read_text(encoding="utf-8")
    assert "activate.bat" not in script
    selection = 'set "VENV_PYTHON=%CD%\\.venv\\Scripts\\python.exe"'
    assert selection in script
    commands = [
        line.strip()
        for line in script.split(selection, 1)[1].splitlines()
        if line.strip()
        .lower()
        .startswith(("python ", "pip ", '"%venv_python%"', 'start ""'))
    ]
    assert commands
    assert all(
        command.startswith('"%VENV_PYTHON%"')
        or command.startswith('start "" /min "%VENV_PYTHON%"')
        for command in commands
    )
    assert any('"%VENV_PYTHON%" -m pip install' in command for command in commands)


@pytest.mark.skipif(sys.platform != "win32", reason="Requires native cmd.exe")
@pytest.mark.parametrize("existing_environment", [False, True])
@pytest.mark.parametrize("skip_via_flag", [False, True])
def test_skip_install_preserves_unusable_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_environment: bool,
    skip_via_flag: bool,
) -> None:
    script = Path("start.bat").read_bytes()
    root = tmp_path / "launcher with spaces"
    root.mkdir()
    (root / "start.bat").write_bytes(script)
    if existing_environment:
        (root / ".venv").mkdir()
        (root / ".venv" / "preserve.txt").write_text("keep", encoding="utf-8")

    def snapshot() -> dict[str, bytes | None]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            if path.is_file()
            else None
            for path in root.rglob("*")
        }

    before = snapshot()
    monkeypatch.chdir(root)
    command = "call start.bat --no-pause"
    if skip_via_flag:
        command += " --skip-install"
    result = _run_batch(
        command,
        timeout=10.0,
        extra_env={"AVCHAIN_SKIP_INSTALL": "0" if skip_via_flag else "1"},
        diagnostic_path=tmp_path / "skip-install-batch.log",
    )
    assert result.returncode == 1, result.stdout
    assert (
        "Virtual environment interpreter missing" in result.stdout
        if existing_environment
        else "Virtual environment missing" in result.stdout
    )
    assert "Installing dependencies" not in result.stdout
    assert "Starting detached service supervisor" not in result.stdout
    assert snapshot() == before


def _run_batch(
    command: str,
    timeout: float = 60.0,
    extra_env: dict[str, str] | None = None,
    diagnostic_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["AVCHAIN_NO_PAUSE"] = "1"
    env["AVCHAIN_SKIP_INSTALL"] = "1"
    env["POLL_INTERVAL"] = "1"
    env["TELEMETRY_RATE"] = "5"
    if extra_env is not None:
        env.update(extra_env)
    # File-backed output avoids a detached child retaining a PIPE and hanging
    # communicate(). Persist native diagnostics when requested, including timeout.
    with (
        diagnostic_path.open("w+b")
        if diagnostic_path is not None
        else tempfile.TemporaryFile(mode="w+b")
    ) as output:
        result = subprocess.run(
            ["cmd", "/c", command],
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            timeout=timeout,
            check=False,
        )
        output.flush()
        output.seek(0)
        captured = output.read().decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(result.args, result.returncode, captured, "")


def _wait_for_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=2.0)
            if response.status_code < 500:
                return
        except Exception as exc:  # pragma: no cover - diagnostic path
            last_error = exc
        time.sleep(0.5)
    raise AssertionError(f"Timed out waiting for {url}: {last_error}")


def _request_with_retry(
    method: str,
    url: str,
    timeout: float = 10.0,
    total_timeout: float = 20.0,
    **kwargs,
) -> httpx.Response:
    deadline = time.time() + total_timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            response = httpx.request(method, url, timeout=timeout, **kwargs)
            response.raise_for_status()
            return response
        except Exception as exc:  # pragma: no cover - diagnostic path
            last_error = exc
            time.sleep(0.5)
    raise AssertionError(f"Timed out waiting for {method} {url}: {last_error}")


def _wait_for_condition(
    predicate,
    timeout: float = 45.0,
    interval: float = 0.5,
) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            if predicate():
                return
            last_error = None
        except Exception as exc:  # pragma: no cover - diagnostic path
            last_error = exc
        time.sleep(interval)
    if last_error is not None:
        raise AssertionError(
            f"Timed out waiting for condition: {last_error}"
        ) from last_error
    raise AssertionError("Timed out waiting for condition")


def _read_status_from(runtime_dir: Path, name: str) -> dict[str, object]:
    status_path = runtime_dir / "status" / f"{name}.json"
    return json.loads(status_path.read_text(encoding="utf-8"))


def _entry_feedback_count(database_path: Path, entry_id: str) -> int:
    connection = sqlite3.connect(database_path)
    try:
        cursor = connection.execute(
            "SELECT COUNT(*) FROM entry_feedback WHERE entry_id = ?",
            (entry_id,),
        )
        return int(cursor.fetchone()[0])
    finally:
        connection.close()


def _status_observation(
    runtime_dir: Path, name: str, max_age_seconds: float = 30.0
) -> dict[str, object]:
    observed_utc = datetime.now(UTC)
    observation: dict[str, object] = {
        "name": name,
        "observed_utc": observed_utc.isoformat(),
        "observed_monotonic": time.monotonic(),
        "fresh": False,
        "max_age_seconds": max_age_seconds,
    }
    try:
        raw = (runtime_dir / "status" / f"{name}.json").read_bytes()
    except OSError as exc:
        observation.update(
            reason="read_error", read_error=f"{type(exc).__name__}: {exc}"
        )
    else:
        observation["raw_hex"] = raw.hex()
        try:
            text = raw.decode("utf-8")
            observation["raw_text"] = text
            payload = json.loads(text)
        except (UnicodeError, json.JSONDecodeError) as exc:
            observation.update(
                reason="invalid_json", read_error=f"{type(exc).__name__}: {exc}"
            )
        else:
            if not isinstance(payload, dict):
                observation["reason"] = "invalid_payload"
            else:
                observation["payload"] = payload
                heartbeat = payload.get("last_heartbeat")
                observation["heartbeat"] = heartbeat
                try:
                    if not isinstance(heartbeat, str):
                        raise ValueError("heartbeat is not a string")
                    observed = datetime.fromisoformat(heartbeat)
                    if observed.tzinfo is None:
                        observed = observed.replace(tzinfo=UTC)
                except ValueError as exc:
                    observation.update(
                        reason="invalid_heartbeat", heartbeat_error=str(exc)
                    )
                else:
                    age = (observed_utc - observed).total_seconds()
                    observation.update(
                        heartbeat_age_seconds=age,
                        fresh=age <= max_age_seconds,
                        reason="fresh" if age <= max_age_seconds else "stale_heartbeat",
                    )
    observation["read_completed_monotonic"] = time.monotonic()
    return observation


def _process_observation(pid: object) -> dict[str, object]:
    result: dict[str, object] = {
        "pid": pid,
        "observed_utc": datetime.now(UTC).isoformat(),
        "observed_monotonic": time.monotonic(),
    }
    if sys.platform != "win32" or not isinstance(pid, int):
        result["state"] = "unavailable"
        return result
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        result.update(state="open_failed", winerror=ctypes.get_last_error())
        return result
    try:
        creation, exit_time, kernel_time, user_time = (
            wintypes.FILETIME() for _ in range(4)
        )
        if kernel.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
            result["creation_utc"] = datetime.fromtimestamp(
                ticks / 10_000_000 - 11_644_473_600, UTC
            ).isoformat()
        else:
            result["creation_query_winerror"] = ctypes.get_last_error()
        exit_code = wintypes.DWORD()
        if kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            result.update(
                exit_code=exit_code.value,
                state="running" if exit_code.value == 259 else "exited",
            )
        else:
            result.update(state="query_failed", winerror=ctypes.get_last_error())
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            result["image_path"] = buffer.value
        else:
            result["image_query_winerror"] = ctypes.get_last_error()
    finally:
        kernel.CloseHandle(handle)
    return result


def _retain_status_failure(runtime_dir: Path, observation: dict[str, object]) -> Path:
    # Only this original read supplies bytes/heartbeat; process inspection is later.
    payload = observation.get("payload")
    pid = payload.get("pid") if isinstance(payload, dict) else None
    later_status = _status_observation(runtime_dir, str(observation["name"]))
    supervisor = _status_observation(runtime_dir, "supervisor")
    supervisor_payload = supervisor.get("payload")
    children = (
        supervisor_payload.get("children", [])
        if isinstance(supervisor_payload, dict)
        else []
    )
    launch_processes = [
        _process_observation(child.get("pid"))
        for child in children
        if isinstance(child, dict) and child.get("service") == observation["name"]
    ]
    later_payload = later_status.get("payload")
    report = {
        "original_read": observation,
        "later_process_observation": _process_observation(pid),
        "later_status_observation": later_status,
        "later_status_process_observation": _process_observation(
            later_payload.get("pid") if isinstance(later_payload, dict) else None
        ),
        "later_supervisor_observation": supervisor,
        "supervisor_launch_process_observations": launch_processes,
    }
    path = runtime_dir.parent / f"heartbeat-failure-{observation['name']}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _status_is_fresh(
    runtime_dir: Path,
    name: str,
    max_age_seconds: float = 30.0,
) -> bool:
    observation = _status_observation(runtime_dir, name, max_age_seconds)
    if not observation["fresh"]:
        _retain_status_failure(runtime_dir, observation)
    return bool(observation["fresh"])


def _assert_status_is_fresh(runtime_dir: Path, name: str) -> None:
    observation = _status_observation(runtime_dir, name)
    if not observation["fresh"]:
        path = _retain_status_failure(runtime_dir, observation)
        raise AssertionError(
            f"Heartbeat failure: {observation}; pre-cleanup evidence: {path}"
        )


def test_heartbeat_diagnostic_retains_original_read(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    status = runtime / "status" / "validator1.json"
    status.parent.mkdir(parents=True)
    original = b'{"unfinished":'
    status.write_bytes(original)

    def later_process(pid):
        status.write_text(json.dumps({"last_heartbeat": datetime.now(UTC).isoformat()}))
        return {
            "pid": pid,
            "state": "unavailable",
            "observed_monotonic": time.monotonic(),
        }

    monkeypatch.setattr(sys.modules[__name__], "_process_observation", later_process)
    with pytest.raises(AssertionError, match="invalid_json"):
        _assert_status_is_fresh(runtime, "validator1")
    report = json.loads((tmp_path / "heartbeat-failure-validator1.json").read_text())
    observed = report["original_read"]
    assert observed["raw_hex"] == original.hex()
    assert observed["raw_text"] == original.decode()
    assert observed["reason"] == "invalid_json"
    assert "JSONDecodeError" in observed["read_error"]
    assert datetime.fromisoformat(observed["observed_utc"]).tzinfo is not None
    assert (
        report["later_process_observation"]["observed_monotonic"]
        >= observed["observed_monotonic"]
    )
    assert json.loads(status.read_bytes())["last_heartbeat"]


@pytest.mark.parametrize("case", ["missing", "old", "invalid-heartbeat"])
def test_heartbeat_diagnostic_distinguishes_failure_causes(tmp_path, case):
    from datetime import timedelta

    runtime = tmp_path / "runtime"
    status = runtime / "status" / "validator1.json"
    status.parent.mkdir(parents=True)
    if case != "missing":
        status.write_text(
            json.dumps(
                {
                    "last_heartbeat": (
                        datetime.now(UTC) - timedelta(seconds=61)
                    ).isoformat()
                    if case == "old"
                    else "invalid"
                }
            )
        )
    observed = _status_observation(runtime, "validator1")
    assert observed["fresh"] is False
    assert (
        observed["reason"]
        == {
            "missing": "read_error",
            "old": "stale_heartbeat",
            "invalid-heartbeat": "invalid_heartbeat",
        }[case]
    )
    if case == "old":
        assert observed["heartbeat_age_seconds"] >= 61


@pytest.mark.e2e
@pytest.mark.skipif(sys.platform != "win32", reason="Windows launcher smoke only")
def test_windows_launchers_keep_background_workers_active(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    evidence_dir = tmp_path / "evidence"
    database_path = tmp_path / "launcher.db"
    extra_env = {
        "DATABASE_URL": f"sqlite:///{database_path.as_posix()}",
        "EVIDENCE_DIR": evidence_dir.as_posix(),
        "VALIDATOR_REGISTRY_PATH": (runtime_dir / "validators.yaml").as_posix(),
    }

    _run_batch("call stop.bat --no-pause", timeout=30.0, extra_env=extra_env)
    try:
        start_result = _run_batch(
            "call start.bat --no-pause --skip-install",
            timeout=240.0,
            extra_env=extra_env,
            diagnostic_path=tmp_path / "start-batch.log",
        )
        assert start_result.returncode == 0, (
            f"start.bat exit={start_result.returncode}\n{start_result.stdout}\n"
            f"Service logs: {runtime_dir / 'logs'}; batch log: "
            f"{tmp_path / 'start-batch.log'}"
        )

        for url in (
            "http://127.0.0.1:8000/docs",
            "http://127.0.0.1:8001/docs",
            "http://127.0.0.1:8002/docs",
            "http://127.0.0.1:8003/docs",
            "http://127.0.0.1:8501",
        ):
            _wait_for_http(url, timeout=30.0)

        for worker_name in ("validator1", "validator2", "validator3", "agent"):
            _wait_for_condition(
                lambda worker_name=worker_name: _status_is_fresh(
                    runtime_dir, worker_name
                ),
                timeout=30.0,
            )

        entry_payload = json.loads(
            (Path("tests") / "fixtures" / "entry_simple.json").read_text(
                encoding="utf-8"
            )
        )
        create_response = _request_with_retry(
            "POST",
            "http://127.0.0.1:8000/ledger/entries",
            json=entry_payload,
            headers={"Authorization": "Bearer dev-ledger-key"},
        )
        entry_id = create_response.json()["id"]

        def _entry() -> dict[str, object]:
            response = _request_with_retry(
                "GET",
                f"http://127.0.0.1:8000/ledger/entries/{entry_id}",
                headers={"Authorization": "Bearer dev-ledger-key"},
            )
            return dict(response.json())

        def _decisions() -> list[dict[str, object]]:
            response = _request_with_retry(
                "GET",
                f"http://127.0.0.1:8002/consensus/decisions/{entry_id}",
                headers={"Authorization": "Bearer dev-consensus-key"},
            )
            return list(response.json())

        _wait_for_condition(lambda: _entry()["state"] == "confirmed", timeout=45.0)
        _wait_for_condition(
            lambda: any(
                decision.get("action") == "promote" for decision in _decisions()
            ),
            timeout=45.0,
        )
        _wait_for_condition(
            lambda: _entry_feedback_count(database_path, entry_id) > 0,
            timeout=45.0,
        )

        coverage_payloads = json.loads(
            (Path("tests") / "fixtures" / "coverage_reports.json").read_text(
                encoding="utf-8"
            )
        )
        for payload in coverage_payloads:
            payload["entry_id"] = entry_id
            _request_with_retry(
                "POST",
                "http://127.0.0.1:8003/coverage/reports",
                json=payload,
                headers={"Authorization": "Bearer dev-coverage-key"},
            )

        def _history_states() -> list[str]:
            return [event["to_state"] for event in _entry()["history"]]

        _wait_for_condition(lambda: "review" in _history_states(), timeout=45.0)
        _wait_for_condition(lambda: _entry()["state"] == "confirmed", timeout=45.0)
        _wait_for_condition(lambda: len(_decisions()) >= 2, timeout=45.0)

        validator_statuses = [
            _read_status_from(runtime_dir, worker_name)
            for worker_name in ("validator1", "validator2", "validator3")
        ]
        agent_status = _read_status_from(runtime_dir, "agent")
        assert any(
            status.get("last_entry_id") == entry_id for status in validator_statuses
        )
        assert agent_status["last_matched_entry_id"] == entry_id
        assert int(agent_status["feedback_generated"]) >= 1

        time.sleep(5.0)
        _wait_for_condition(lambda: _entry()["state"] == "confirmed", timeout=20.0)
        for worker_name in ("validator1", "validator2", "validator3", "agent"):
            _assert_status_is_fresh(runtime_dir, worker_name)
    finally:
        stop_result = _run_batch(
            "call stop.bat --no-pause",
            timeout=30.0,
            extra_env=extra_env,
            diagnostic_path=tmp_path / "stop-batch.log",
        )
        assert stop_result.returncode == 0, stop_result.stdout


def test_batch_helper_retains_failure_diagnostics(tmp_path, monkeypatch):
    def failed_run(command, **kwargs):
        assert kwargs["stderr"] == subprocess.STDOUT
        kwargs["stdout"].write(b"preflight diagnostic\n")
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(subprocess, "run", failed_run)
    log = tmp_path / "batch.log"
    result = _run_batch("call start.bat", diagnostic_path=log)
    assert result.returncode == 1
    assert result.stdout == "preflight diagnostic\n"
    assert log.read_text() == result.stdout


def test_batch_helper_retains_output_on_timeout(tmp_path, monkeypatch):
    def timed_out(command, **kwargs):
        kwargs["stdout"].write(b"diagnostic before timeout\n")
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", timed_out)
    log = tmp_path / "batch.log"
    with pytest.raises(subprocess.TimeoutExpired):
        _run_batch("call start.bat", diagnostic_path=log)
    assert log.read_text() == "diagnostic before timeout\n"
