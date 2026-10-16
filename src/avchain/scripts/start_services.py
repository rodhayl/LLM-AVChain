from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path

import httpx

from avchain.config.settings import get_settings
from avchain.database.core import init_db
from avchain.scripts.generate_keys import (
    generate_endpoint_material,
    generate_validator_material,
)
from avchain.utils.helpers import current_timestamp
from avchain.utils.runtime_status import (
    is_status_fresh,
    log_path,
    read_status,
    status_dir,
    write_status,
)


def ensure_runtime_prerequisites() -> None:
    settings = get_settings()
    init_db(settings.database_url)
    registry_path = Path(settings.validator_registry_path)
    if not registry_path.exists():
        generate_validator_material(
            output_dir=registry_path.parent or Path("."),
            num_validators=3,
        )
    endpoint_registry_path = Path(settings.endpoint_registry_path)
    endpoint_key_path = Path(settings.endpoint_private_key_path)
    if not endpoint_registry_path.exists() or not endpoint_key_path.exists():
        generate_endpoint_material(
            output_dir=endpoint_registry_path.parent or Path("."),
            endpoint_id=settings.endpoint_id,
        )


def ensure_ports_available(host: str, ports: Iterable[int]) -> None:
    unavailable: list[int] = []
    for port in ports:
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError:
                unavailable.append(port)
    if unavailable:
        ports_text = ", ".join(str(port) for port in unavailable)
        raise RuntimeError(f"Required ports are already in use: {ports_text}")


def service_urls() -> tuple[str, ...]:
    settings = get_settings()
    return (
        f"http://127.0.0.1:{settings.port_ledger}/docs",
        f"http://127.0.0.1:{settings.port_evidence}/docs",
        f"http://127.0.0.1:{settings.port_consensus}/docs",
        f"http://127.0.0.1:{settings.port_coverage}/docs",
        "http://127.0.0.1:8501",
    )


def wait_for_service_urls(timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    pending = set(service_urls())
    last_errors: dict[str, str] = {}

    while time.time() < deadline and pending:
        for url in list(pending):
            try:
                response = httpx.get(url, timeout=2.0)
                if response.status_code < 500:
                    pending.remove(url)
                    last_errors.pop(url, None)
                    continue
                last_errors[url] = f"HTTP {response.status_code}"
            except httpx.HTTPError as exc:
                last_errors[url] = str(exc)
        if pending:
            time.sleep(0.5)

    if pending:
        details = "; ".join(
            f"{url}: {last_errors.get(url, 'not reachable')}" for url in sorted(pending)
        )
        raise RuntimeError(f"Timed out waiting for services to become ready: {details}")


def worker_status_names() -> tuple[str, ...]:
    return ("validator1", "validator2", "validator3", "agent")


def wait_for_worker_statuses(
    timeout: float = 60.0,
    freshness_seconds: float = 30.0,
) -> None:
    deadline = time.time() + timeout
    pending = set(worker_status_names())

    while time.time() < deadline and pending:
        for name in list(pending):
            payload = read_status(name)
            if payload is None:
                continue
            if is_status_fresh(payload, freshness_seconds=freshness_seconds):
                pending.remove(name)
        if pending:
            time.sleep(0.5)

    if pending:
        expected = ", ".join(sorted(pending))
        raise RuntimeError(
            f"Timed out waiting for worker heartbeats in {status_dir()}: {expected}"
        )


def start_process(command: list[str], title: str) -> subprocess.Popen[bytes]:
    service_name = title.lower()
    log_handle = log_path(service_name).open("ab")
    process_env = os.environ.copy()
    process_env["PYTHONUNBUFFERED"] = "1"
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
            subprocess, "DETACHED_PROCESS", 0
        )
        process = subprocess.Popen(
            command,
            creationflags=creationflags,
            env=process_env,
            stdout=log_handle,
            stderr=log_handle,
        )
        log_handle.close()
        return process
    process = subprocess.Popen(
        command,
        env=process_env,
        stdout=log_handle,
        stderr=log_handle,
    )
    log_handle.close()
    return process


def _log_supervisor(message: str) -> None:
    line = f"{current_timestamp().isoformat()} {message}\n"
    with log_path("supervisor").open("a", encoding="utf-8") as handle:
        handle.write(line)


def main() -> None:
    ensure_runtime_prerequisites()
    settings = get_settings()
    registry_dir = Path(settings.validator_registry_path).parent or Path(".")
    keys_dir = registry_dir / "keys"
    ensure_ports_available(
        "127.0.0.1",
        (
            settings.port_ledger,
            settings.port_evidence,
            settings.port_consensus,
            settings.port_coverage,
            8501,
        ),
    )
    ledger_command = [
        sys.executable,
        "-m",
        "uvicorn",
        "avchain.ledger.service:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(settings.port_ledger),
    ]
    evidence_command = [
        sys.executable,
        "-m",
        "uvicorn",
        "avchain.evidence.service:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(settings.port_evidence),
    ]
    consensus_command = [
        sys.executable,
        "-m",
        "uvicorn",
        "avchain.consensus.service:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(settings.port_consensus),
    ]
    coverage_command = [
        sys.executable,
        "-m",
        "uvicorn",
        "avchain.coverage.service:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(settings.port_coverage),
    ]
    dashboard_command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "src/avchain/dashboard/app.py",
        "--server.address",
        "127.0.0.1",
        "--server.port",
        "8501",
        "--server.headless",
        "true",
    ]
    processes = [
        ("Ledger", ledger_command),
        ("Evidence", evidence_command),
        ("Consensus", consensus_command),
        ("Coverage", coverage_command),
        (
            "Validator1",
            [
                sys.executable,
                "-m",
                "avchain.validator.worker",
                "validator1",
                str(keys_dir / "validator1_key.pem"),
            ],
        ),
        (
            "Validator2",
            [
                sys.executable,
                "-m",
                "avchain.validator.worker",
                "validator2",
                str(keys_dir / "validator2_key.pem"),
            ],
        ),
        (
            "Validator3",
            [
                sys.executable,
                "-m",
                "avchain.validator.worker",
                "validator3",
                str(keys_dir / "validator3_key.pem"),
            ],
        ),
        ("Agent", [sys.executable, "-m", "avchain.agent.worker"]),
        ("Dashboard", dashboard_command),
    ]

    spawned: list[subprocess.Popen[bytes]] = []
    try:
        for title, command in processes:
            spawned.append(start_process(command, title))
        _log_supervisor(
            "spawned children: "
            + ", ".join(
                f"{title.lower()}={process.pid}"
                for (title, _), process in zip(processes, spawned, strict=True)
            )
        )
        write_status(
            "supervisor",
            {
                "state": "running",
                "children": [
                    {"service": title.lower(), "pid": process.pid}
                    for (title, _), process in zip(processes, spawned, strict=True)
                ],
            },
        )
        print("Started services:")
        for (title, _), process in zip(processes, spawned, strict=True):
            print(f"  {title}: pid={process.pid}, log={log_path(title.lower())}")

        while True:
            failed = [
                (title, process.returncode)
                for (title, _), process in zip(processes, spawned, strict=True)
                if process.poll() is not None
            ]
            if failed:
                _log_supervisor(
                    "detected exited processes: "
                    + ", ".join(
                        f"{title.lower()}={returncode}" for title, returncode in failed
                    )
                )
                write_status(
                    "supervisor",
                    {
                        "state": "failed",
                        "failed_services": [
                            {"service": title.lower(), "returncode": returncode}
                            for title, returncode in failed
                        ],
                    },
                )
                raise RuntimeError(
                    "Service supervisor detected exited processes: "
                    + ", ".join(
                        f"{title}({returncode})" for title, returncode in failed
                    )
                )
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for process in spawned:
            if process.poll() is None:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        capture_output=True,
                        check=False,
                    )
                else:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        _log_supervisor("supervisor stopped")
        try:
            write_status("supervisor", {"state": "stopped"})
        except OSError as exc:
            _log_supervisor(f"status publication failed while stopping: {exc}")


if __name__ == "__main__":
    if "--preflight" in sys.argv:
        ensure_runtime_prerequisites()
        settings = get_settings()
        ensure_ports_available(
            "127.0.0.1",
            (
                settings.port_ledger,
                settings.port_evidence,
                settings.port_consensus,
                settings.port_coverage,
                8501,
            ),
        )
        print("Startup preflight passed.")
    elif "--wait-ready" in sys.argv:
        wait_for_service_urls()
        wait_for_worker_statuses()
        print("Service readiness checks passed.")
    else:
        main()
