from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from avchain.models.schemas import TelemetryEvent


def collect_artifacts(
    watch_dir: str | Path,
    *,
    max_file_size_bytes: int,
) -> list[Path]:
    root = Path(watch_dir)
    if not root.exists():
        return []
    artifacts = [
        path
        for path in root.rglob("*")
        if path.is_file() and path.stat().st_size <= max_file_size_bytes
    ]
    return sorted(artifacts, key=_artifact_sort_key)


def _artifact_sort_key(path: Path) -> tuple[int, str]:
    priority = 0 if path.name == "package.json" else 1
    return (priority, str(path))


def collect_external_telemetry(
    *event_paths: str | Path,
) -> list[TelemetryEvent]:
    events: list[TelemetryEvent] = []
    for raw_path in event_paths:
        if not raw_path:
            continue
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            events.append(TelemetryEvent.model_validate(payload))
    return events


def collect_native_snapshot_telemetry(limit: int = 25) -> list[TelemetryEvent]:
    events: list[TelemetryEvent] = []
    events.extend(_collect_process_snapshot(limit=limit))
    events.extend(_collect_package_snapshot(limit=limit))
    events.extend(_collect_network_snapshot(limit=limit))
    events.extend(_collect_powershell_event_snapshot(limit=limit))
    events.extend(_collect_command_history_snapshot(limit=limit))
    deduplicated: list[TelemetryEvent] = []
    seen_observables: set[str] = set()
    for event in events:
        if event.observable in seen_observables:
            continue
        seen_observables.add(event.observable)
        deduplicated.append(event)
    return deduplicated[:limit]


def _collect_process_snapshot(limit: int) -> list[TelemetryEvent]:
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            check=False,
        )
        lines = result.stdout.splitlines()
        events = []
        for raw_line in lines[:limit]:
            parts = [part.strip('"') for part in raw_line.split('","')]
            if not parts or not parts[0]:
                continue
            process_name = parts[0].lower()
            events.append(
                TelemetryEvent(
                    observable=f"process:{process_name}",
                    metadata={"process_name": process_name, "source": "tasklist"},
                )
            )
        return events
    result = subprocess.run(
        ["ps", "-eo", "comm="],
        capture_output=True,
        text=True,
        check=False,
    )
    events = []
    for process_name in result.stdout.splitlines()[:limit]:
        process_name = process_name.strip().lower()
        if not process_name:
            continue
        events.append(
            TelemetryEvent(
                observable=f"process:{process_name}",
                metadata={"process_name": process_name, "source": "ps"},
            )
        )
    return events


def _collect_package_snapshot(limit: int) -> list[TelemetryEvent]:
    result = subprocess.run(
        ["python", "-m", "pip", "list", "--format=json"],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        packages = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return []
    events: list[TelemetryEvent] = []
    for package in packages[:limit]:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name:
            continue
        events.append(
            TelemetryEvent(
                observable=f"package:{name.lower()}",
                metadata={"package_name": name.lower(), "version": version or ""},
            )
        )
    return events


def _collect_network_snapshot(limit: int) -> list[TelemetryEvent]:
    if os.name == "nt":
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            check=False,
        )
    else:
        result = subprocess.run(
            ["netstat", "-an"],
            capture_output=True,
            text=True,
            check=False,
        )
    events: list[TelemetryEvent] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        remote = parts[2]
        if remote in {"*", "0.0.0.0:0"} or ":" not in remote:
            continue
        remote_host = remote.rsplit(":", 1)[0].strip("[]").lower()
        if not remote_host:
            continue
        events.append(
            TelemetryEvent(
                observable=f"network:{remote_host}",
                metadata={"remote_host": remote_host, "source": "netstat"},
            )
        )
        if len(events) >= limit:
            break
    return events


def _collect_command_history_snapshot(limit: int) -> list[TelemetryEvent]:
    events: list[TelemetryEvent] = []
    for history_path in _history_candidate_paths():
        if not history_path.exists() or not history_path.is_file():
            continue
        try:
            lines = history_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for raw_line in reversed(lines):
            command = raw_line.strip()
            if not command:
                continue
            for observable in _command_observables(command):
                events.append(
                    TelemetryEvent(
                        observable=observable,
                        metadata={
                            "source": str(history_path),
                            "command_excerpt": command[:160],
                        },
                    )
                )
                if len(events) >= limit:
                    return events
    return events


def _collect_powershell_event_snapshot(limit: int) -> list[TelemetryEvent]:
    if os.name != "nt":
        return []
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' "
            "-MaxEvents 25 | Select-Object -ExpandProperty Message"
        ),
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    events: list[TelemetryEvent] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        for observable in _command_observables(line):
            events.append(
                TelemetryEvent(
                    observable=observable,
                    metadata={
                        "source": "powershell_operational_log",
                        "command_excerpt": line[:160],
                    },
                )
            )
            if len(events) >= limit:
                return events
    return events


def _history_candidate_paths() -> list[Path]:
    candidates: list[Path] = []
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(
                Path(appdata)
                / "Microsoft"
                / "Windows"
                / "PowerShell"
                / "PSReadLine"
                / "ConsoleHost_history.txt"
            )
    else:
        try:
            home = Path.home()
        except RuntimeError:
            pass
        else:
            candidates.extend([home / ".bash_history", home / ".zsh_history"])
    deduplicated: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        candidate_text = str(candidate)
        if candidate_text in seen:
            continue
        seen.add(candidate_text)
        deduplicated.append(candidate)
    return deduplicated


def _command_observables(command: str) -> list[str]:
    text = command.lower()
    observables: list[str] = []
    if "powershell" in text and (
        "invoke-webrequest" in text or "downloadstring" in text or "iwr " in text
    ):
        observables.append("command:powershell-download")
    if " -enc " in text or " -encodedcommand " in text:
        observables.append("command:encodedcommand")
    if "curl " in text or "wget " in text:
        observables.append("command:network-download")
    if "npm install" in text or "pip install" in text:
        observables.append("command:package-install")
    if "postinstall" in text:
        observables.append("command:postinstall")
    return observables
