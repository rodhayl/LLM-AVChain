from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

import httpx
import pytest

from avchain.scripts.generate_keys import generate_validator_material


@dataclass
class ManagedProcess:
    process: subprocess.Popen[str]
    log_handle: TextIO
    log_path: Path


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_http(url: str, timeout: float = 30.0) -> httpx.Response:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=2.0)
            if response.status_code < 500:
                return response
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
    predicate, timeout: float = 30.0, interval: float = 0.5
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


def _spawn(
    command: list[str],
    env: dict[str, str],
    log_path: Path,
) -> ManagedProcess:
    log_handle = log_path.open("w", encoding="utf-8")
    process_env = dict(env)
    process_env["PYTHONUNBUFFERED"] = "1"
    process = subprocess.Popen(
        command,
        env=process_env,
        stdout=log_handle,
        stderr=log_handle,
        text=True,
    )
    return ManagedProcess(process=process, log_handle=log_handle, log_path=log_path)


def _log_tail(log_path: Path, lines: int = 40) -> str:
    if not log_path.exists():
        return ""
    content = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


def _format_process_logs(processes: list[ManagedProcess]) -> str:
    sections = []
    for managed in processes:
        managed.log_handle.flush()
        tail = _log_tail(managed.log_path)
        if tail:
            sections.append(f"== {managed.log_path.name} ==\n{tail}")
    return "\n\n".join(sections)


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


@pytest.mark.e2e
def test_live_process_stack_smoke(tmp_path: Path) -> None:
    ledger_port = _free_port()
    evidence_port = _free_port()
    consensus_port = _free_port()
    coverage_port = _free_port()
    dashboard_port = _free_port()

    registry_path = generate_validator_material(tmp_path, num_validators=3)
    database_path = tmp_path / "ledger.db"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": f"sqlite:///{database_path.as_posix()}",
            "EVIDENCE_DIR": evidence_dir.as_posix(),
            "VALIDATOR_REGISTRY_PATH": registry_path.as_posix(),
            "LEDGER_API_KEY": "live-ledger-key",
            "EVIDENCE_API_KEY": "live-evidence-key",
            "CONSENSUS_API_KEY": "live-consensus-key",
            "COVERAGE_API_KEY": "live-coverage-key",
            "AGENT_API_KEY": "live-agent-key",
            "LEDGER_BASE_URL": f"http://127.0.0.1:{ledger_port}",
            "EVIDENCE_BASE_URL": f"http://127.0.0.1:{evidence_port}",
            "CONSENSUS_BASE_URL": f"http://127.0.0.1:{consensus_port}",
            "COVERAGE_BASE_URL": f"http://127.0.0.1:{coverage_port}",
            "PORT_LEDGER": str(ledger_port),
            "PORT_EVIDENCE": str(evidence_port),
            "PORT_CONSENSUS": str(consensus_port),
            "PORT_COVERAGE": str(coverage_port),
            "PORT_AGENT": str(_free_port()),
            "POLL_INTERVAL": "1",
            "TELEMETRY_RATE": "5",
        }
    )

    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    processes: list[ManagedProcess] = []
    try:
        processes.extend(
            [
                _spawn(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "avchain.ledger.service:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(ledger_port),
                    ],
                    env,
                    log_dir / "ledger.log",
                ),
                _spawn(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "avchain.evidence.service:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(evidence_port),
                    ],
                    env,
                    log_dir / "evidence.log",
                ),
                _spawn(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "avchain.consensus.service:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(consensus_port),
                    ],
                    env,
                    log_dir / "consensus.log",
                ),
                _spawn(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "avchain.coverage.service:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(coverage_port),
                    ],
                    env,
                    log_dir / "coverage.log",
                ),
                _spawn(
                    [
                        sys.executable,
                        "-m",
                        "avchain.validator.worker",
                        "validator1",
                        str(registry_path.parent / "keys" / "validator1_key.pem"),
                    ],
                    env,
                    log_dir / "validator1.log",
                ),
                _spawn(
                    [
                        sys.executable,
                        "-m",
                        "avchain.validator.worker",
                        "validator2",
                        str(registry_path.parent / "keys" / "validator2_key.pem"),
                    ],
                    env,
                    log_dir / "validator2.log",
                ),
                _spawn(
                    [sys.executable, "-m", "avchain.agent.worker"],
                    env,
                    log_dir / "agent.log",
                ),
                _spawn(
                    [
                        sys.executable,
                        "-m",
                        "streamlit",
                        "run",
                        "src/avchain/dashboard/app.py",
                        "--server.port",
                        str(dashboard_port),
                        "--server.headless",
                        "true",
                    ],
                    env,
                    log_dir / "dashboard.log",
                ),
            ]
        )

        _wait_for_http(f"http://127.0.0.1:{ledger_port}/docs")
        _wait_for_http(f"http://127.0.0.1:{evidence_port}/docs")
        _wait_for_http(f"http://127.0.0.1:{consensus_port}/docs")
        _wait_for_http(f"http://127.0.0.1:{coverage_port}/docs")
        dashboard_response = _wait_for_http(f"http://127.0.0.1:{dashboard_port}")
        assert dashboard_response.status_code == 200

        entry_payload = json.loads(
            (Path("tests") / "fixtures" / "entry_simple.json").read_text(
                encoding="utf-8"
            )
        )
        create_response = _request_with_retry(
            "POST",
            f"http://127.0.0.1:{ledger_port}/ledger/entries",
            json=entry_payload,
            headers={"Authorization": "Bearer live-ledger-key"},
        )
        entry_id = create_response.json()["id"]

        def entry_state() -> str:
            response = _request_with_retry(
                "GET",
                f"http://127.0.0.1:{ledger_port}/ledger/entries/{entry_id}",
                headers={"Authorization": "Bearer live-ledger-key"},
            )
            return str(response.json()["state"])

        _wait_for_condition(lambda: entry_state() == "confirmed", timeout=20.0)
        _wait_for_condition(
            lambda: _entry_feedback_count(database_path, entry_id) > 0,
            timeout=20.0,
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
                f"http://127.0.0.1:{coverage_port}/coverage/reports",
                json=payload,
                headers={"Authorization": "Bearer live-coverage-key"},
            )

        def history_has_review() -> bool:
            response = _request_with_retry(
                "GET",
                f"http://127.0.0.1:{ledger_port}/ledger/entries/{entry_id}",
                headers={"Authorization": "Bearer live-ledger-key"},
            )
            history = response.json()["history"]
            return any(event["to_state"] == "review" for event in history)

        _wait_for_condition(history_has_review, timeout=20.0)
        _wait_for_condition(lambda: entry_state() == "confirmed", timeout=20.0)
    except Exception as exc:
        logs = _format_process_logs(processes)
        message = str(exc)
        if logs:
            message = f"{message}\n\nProcess logs:\n{logs}"
        raise AssertionError(message) from exc
    finally:
        for managed in reversed(processes):
            process = managed.process
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            managed.log_handle.close()
