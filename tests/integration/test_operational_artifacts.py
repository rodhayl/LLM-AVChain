from __future__ import annotations

from pathlib import Path

import yaml


def test_docker_compose_defines_full_stack() -> None:
    compose_path = Path("docker-compose.yml")
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = compose["services"]
    assert {
        "bootstrap",
        "ledger",
        "evidence",
        "consensus",
        "coverage",
        "validator1",
        "validator2",
        "validator3",
        "agent",
        "dashboard",
    }.issubset(services)

    for service_name in ("ledger", "evidence", "consensus", "coverage", "dashboard"):
        assert (
            services[service_name]["environment"]["DATABASE_URL"]
            == "sqlite:////data/ledger.db"
        )
    assert (
        services["consensus"]["environment"]["LEDGER_API_KEY"]
        == "${LEDGER_API_KEY:-dev-ledger-key}"
    )
    assert (
        services["coverage"]["environment"]["CONSENSUS_API_KEY"]
        == "${CONSENSUS_API_KEY:-dev-consensus-key}"
    )
    assert (
        services["consensus"]["depends_on"]["bootstrap"]["condition"]
        == "service_completed_successfully"
    )


def test_windows_launchers_support_noninteractive_smoke() -> None:
    start_script = Path("start.bat").read_text(encoding="utf-8")
    stop_script = Path("stop.bat").read_text(encoding="utf-8")

    assert "--no-pause" in start_script
    assert "--no-pause" in stop_script
    assert "AVCHAIN_SKIP_INSTALL" in start_script
    # Verify the selected-environment contract, not a historical refresh flag.
    assert 'set "VENV_PYTHON=%CD%\\.venv\\Scripts\\python.exe"' in start_script
    assert "activate.bat" not in start_script
    assert '"%VENV_PYTHON%" -m pip install' in start_script
    assert ':startup_failed\nif "%NO_PAUSE%"=="1" exit /b 1' in start_script
    assert "generate_keys" in start_script
    assert "--wait-ready" in start_script
    assert r"runtime\validators.yaml" in start_script
    assert r"runtime\logs" in start_script or "runtime/logs" in start_script
    assert "stop_services" in stop_script
    assert "docker compose down -v --remove-orphans" in stop_script
