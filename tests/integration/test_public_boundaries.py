"""Keep a public research checkout inside its documented local trust boundary."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from avchain.scripts import start_services


def test_compose_published_ports_are_loopback_only() -> None:
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    published = {
        name: service["ports"]
        for name, service in compose["services"].items()
        if "ports" in service
    }
    assert set(published) == {
        "ledger",
        "evidence",
        "consensus",
        "coverage",
        "dashboard",
    }
    for ports in published.values():
        assert ports
        assert all(str(port).startswith("127.0.0.1:") for port in ports)


def test_native_dashboard_is_loopback_only(monkeypatch) -> None:
    commands = {}

    def spawn(command, title):
        commands[title] = command
        return SimpleNamespace(pid=100 + len(commands), poll=lambda: 0)

    def stop_after_spawn(*args):
        raise OSError("finished command capture")

    monkeypatch.setattr(start_services, "ensure_runtime_prerequisites", lambda: None)
    monkeypatch.setattr(start_services, "ensure_ports_available", lambda *args: None)
    monkeypatch.setattr(start_services, "start_process", spawn)
    monkeypatch.setattr(start_services, "write_status", stop_after_spawn)
    monkeypatch.setattr(start_services, "_log_supervisor", lambda message: None)
    with pytest.raises(OSError, match="finished command capture"):
        start_services.main()
    command = commands["Dashboard"]
    assert command[command.index("--server.address") + 1] == "127.0.0.1"


def test_docker_build_input_contains_project_license() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    assert "COPY pyproject.toml README.md LICENSE ./" in dockerfile


def test_ci_uses_ephemeral_runner_and_minimum_permissions() -> None:
    workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text("utf-8"))
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["test"]
    # Never direct public pull-request code toward a persistent local runner.
    events = workflow.get("on", workflow.get(True))
    assert set(events) == {"push", "pull_request", "workflow_dispatch"}
    assert events["push"]["branches"] == ["main"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert "self-hosted" not in str(workflow)
    assert "pull_request_target" not in events
    checkout = next(
        step for step in job["steps"] if "actions/checkout@" in step.get("uses", "")
    )
    assert checkout["with"]["persist-credentials"] is False
    actions = [step["uses"] for step in job["steps"] if "uses" in step]
    assert all(len(action.rsplit("@", 1)[1]) == 40 for action in actions)
    assert all("upload-artifact" not in action for action in actions)
