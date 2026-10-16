from __future__ import annotations

import pytest

from avchain.incident.triage import IncidentTriage
from avchain.scripts.run_incident_demo import run_lab


@pytest.mark.asyncio
async def test_two_nodes_share_validated_package_without_code_change(
    test_environment, tmp_path
):
    report = await run_lab(tmp_path, IncidentTriage(), replay=False)
    assert report["mode"] == "rules"
    assert report["real_model_executed"] is False
    assert report["two_nodes_same_package"] is True
    assert report["node_b_code_changed"] is False
    assert report["code_digest_before"] == report["code_digest_after"]
    for name in ("node_a", "node_b"):
        assert report["nodes"][name]["receipt"]["status"] == "applied"
        assert report["nodes"][name]["recovery"]["status"] == "rolled_back"
        assert (
            report["nodes"][name]["receipt"]["package_digest"]
            == report["package_digest"]
        )
        assert (
            report["nodes"][name]["analysis"]["input_digest"]
            == report["rule_comparison"][name]["input_digest"]
        )
    assert report["nodes"]["benign"]["unchanged"] is True
    assert report["nodes"]["benign"]["analysis"]["output"]["actions"] == []


def test_fixture_process_preserves_windows_bootstrap_only(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from avchain.incident.lab import create_lab_fixture
    from avchain.scripts.run_incident_demo import LoopbackCanary

    root = tmp_path / "owned"
    create_lab_fixture(root)
    canary = LoopbackCanary.__new__(LoopbackCanary)
    canary.hits = []
    canary.server = SimpleNamespace(server_port=12345)
    captured = {}

    def run(command, **kwargs):
        captured.update(kwargs)

    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setenv("WINDIR", "C:\\Windows")
    monkeypatch.setattr("avchain.scripts.run_incident_demo.sys.platform", "win32")
    monkeypatch.setenv("UNRELATED_TEST_SECRET", "must-not-copy")
    monkeypatch.setattr("avchain.scripts.run_incident_demo.subprocess.run", run)
    assert canary.replay_owned_fixture(root) == 0
    assert captured["env"] == {
        "SystemRoot": "C:\\Windows",
        "WINDIR": "C:\\Windows",
        "AVCHAIN_DEMO_PORT": "12345",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    assert captured["timeout"] == 10


def test_fixture_env_uses_only_current_shared_python_library(tmp_path, monkeypatch):
    from avchain.scripts import run_incident_demo as demo

    library_dir = tmp_path / "lib"
    library_dir.mkdir()
    (library_dir / "libpython.so").write_bytes(b"test-only library marker")
    monkeypatch.setattr(demo.sys, "platform", "linux")
    monkeypatch.setattr(demo.sys, "base_prefix", str(tmp_path))
    config = {"Py_ENABLE_SHARED": 1, "LDLIBRARY": "libpython.so"}
    monkeypatch.setattr(demo.sysconfig, "get_config_var", config.get)
    for name in ("SystemRoot", "WINDIR"):
        monkeypatch.delenv(name, raising=False)
    for name in (
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONPATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "UNRELATED_TEST_SECRET",
    ):
        monkeypatch.setenv(name, "must-not-copy")

    assert demo._fixture_child_env(12345) == {
        "AVCHAIN_DEMO_PORT": "12345",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LD_LIBRARY_PATH": str(library_dir),
    }


@pytest.mark.parametrize(
    "platform, shared, library_name",
    [
        ("linux", 0, "libpython.so"),
        ("win32", 1, "libpython.so"),
        ("darwin", 1, "libpython.so"),
        ("linux", 1, None),
        ("linux", 1, ""),
        ("linux", 1, "../libpython.so"),
        ("linux", 1, "/outside/libpython.so"),
        ("linux", 1, "missing.so"),
    ],
)
def test_fixture_env_does_not_guess_loader_paths(
    tmp_path, monkeypatch, platform, shared, library_name
):
    from avchain.scripts import run_incident_demo as demo

    library_dir = tmp_path / "lib"
    library_dir.mkdir()
    (library_dir / "libpython.so").write_bytes(b"test-only library marker")
    monkeypatch.setattr(demo.sys, "platform", platform)
    monkeypatch.setattr(demo.sys, "base_prefix", str(tmp_path))
    config = {"Py_ENABLE_SHARED": shared, "LDLIBRARY": library_name}
    monkeypatch.setattr(demo.sysconfig, "get_config_var", config.get)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/unrelated/library/path")
    for name in ("SystemRoot", "WINDIR"):
        monkeypatch.delenv(name, raising=False)

    assert demo._fixture_child_env(12345) == {
        "AVCHAIN_DEMO_PORT": "12345",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


@pytest.mark.parametrize("escape", ["library_file", "library_directory"])
def test_fixture_env_rejects_loader_symlinks_outside_interpreter_prefix(
    tmp_path, monkeypatch, escape
):
    from avchain.scripts import run_incident_demo as demo

    base = tmp_path / "python"
    base.mkdir()
    library_dir = base / "lib"
    try:
        if escape == "library_file":
            library_dir.mkdir()
            outside = tmp_path / "outside.so"
            outside.write_bytes(b"test-only outside library marker")
            (library_dir / "libpython.so").symlink_to(outside)
        else:
            outside_dir = tmp_path / "outside"
            outside_dir.mkdir()
            library = base / "libpython.so"
            library.write_bytes(b"test-only trusted library marker")
            (outside_dir / "libpython.so").symlink_to(library)
            library_dir.symlink_to(outside_dir, target_is_directory=True)
    except OSError:
        pytest.skip("Library symlink creation unavailable")
    monkeypatch.setattr(demo.sys, "platform", "linux")
    monkeypatch.setattr(demo.sys, "base_prefix", str(base))
    config = {"Py_ENABLE_SHARED": 1, "LDLIBRARY": "libpython.so"}
    monkeypatch.setattr(demo.sysconfig, "get_config_var", config.get)
    assert "LD_LIBRARY_PATH" not in demo._fixture_child_env(12345)


@pytest.mark.parametrize("failure", ["timeout", "exit"])
def test_demo_subprocess_failures_keep_blocked_report(tmp_path, monkeypatch, failure):
    import json
    import subprocess

    from avchain.scripts import run_incident_demo

    async def fail(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired("owned-fixture", timeout=10)
        raise subprocess.CalledProcessError(1, "owned-fixture")

    report = tmp_path / "result.json"
    monkeypatch.setattr(run_incident_demo, "run_lab", fail)
    monkeypatch.setattr(
        "sys.argv", ["run_incident_demo", "--mode", "rules", "--output", str(report)]
    )
    assert run_incident_demo.main() == 2
    result = json.loads(report.read_text())
    assert result["status"] == "blocked_or_inconclusive"
    assert result["fallback_used"] is False


@pytest.mark.asyncio
async def test_first_replay_failure_closes_owned_collector(
    test_environment, tmp_path, monkeypatch
):
    import subprocess

    from avchain.scripts import run_incident_demo

    closed = []

    class FailingCanary:
        def replay_owned_fixture(self, root):
            raise subprocess.TimeoutExpired("owned-fixture", timeout=10)

        def close(self):
            closed.append(True)

    monkeypatch.setattr(run_incident_demo, "LoopbackCanary", FailingCanary)
    with pytest.raises(subprocess.TimeoutExpired):
        await run_incident_demo.run_lab(tmp_path, IncidentTriage())
    assert closed == [True]


def test_cli_import_does_not_initialize_inherited_evidence_path(tmp_path, monkeypatch):
    import subprocess
    import sys

    inherited = tmp_path / "real-evidence-must-stay-absent"
    monkeypatch.setenv("EVIDENCE_DIR", str(inherited))
    subprocess.run(
        [sys.executable, "-c", "import avchain.scripts.run_incident_demo"],
        check=True,
        capture_output=True,
        timeout=10,
    )
    assert not inherited.exists()


@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("reasoning", ["server_default", "off"])
def test_cli_retains_explicit_model_configuration_on_success_and_failure(
    tmp_path, monkeypatch, failure, reasoning
):
    import json

    from avchain.scripts import run_incident_demo

    async def run_lab_without_inference(root, triage, **kwargs):
        assert triage.model.max_tokens == 3072
        assert triage.model.client.timeout_seconds == 300
        assert triage.model.client.max_retries == 0
        assert triage.model.reasoning == reasoning
        if failure:
            raise RuntimeError("test-only failure before inference")
        return {"mode": "test_double", "real_model_executed": False}

    report = tmp_path / "result.json"
    monkeypatch.setattr(run_incident_demo, "run_lab", run_lab_without_inference)
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_incident_demo",
            "--mode",
            "local_llm",
            "--model",
            "test-only",
            "--max-tokens",
            "3072",
            "--timeout-seconds",
            "300",
            "--reasoning",
            reasoning,
            "--output",
            str(report),
        ],
    )
    assert run_incident_demo.main() == (2 if failure else 0)
    result = json.loads(report.read_text())
    assert result["real_model_executed"] is False
    assert result["model_request_diagnostics"] == []
    assert result["model_configuration"] == {
        "model": "test-only",
        "timeout_seconds": 300,
        "timeout_scope": "per_request_wall_clock",
        "max_tokens": 3072,
        "response_format": "json_schema",
        "temperature": 0,
        "max_retries": 0,
        "reasoning": "off_requested"
        if reasoning == "off"
        else "server_default_unchanged",
        **({"reasoning_effort": "none"} if reasoning == "off" else {}),
    }
    assert result["model_reasoning_capability"] is None


@pytest.mark.parametrize("max_tokens", ["0", "-1", "4097", "3.5"])
def test_cli_rejects_invalid_budget_before_creating_lab(
    tmp_path, monkeypatch, max_tokens
):
    from avchain.scripts import run_incident_demo

    def must_not_create_lab(*args, **kwargs):
        pytest.fail("Invalid budget must fail before the laboratory starts")

    monkeypatch.setattr(
        run_incident_demo.tempfile, "TemporaryDirectory", must_not_create_lab
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_incident_demo",
            "--mode",
            "local_llm",
            "--model",
            "test-only",
            "--max-tokens",
            max_tokens,
            "--output",
            str(tmp_path / "must-not-exist.json"),
        ],
    )
    with pytest.raises(SystemExit) as error:
        run_incident_demo.main()
    assert error.value.code == 2


@pytest.mark.parametrize("failure", ["timeout", "metadata", "http"])
def test_cli_off_capability_failure_keeps_blocked_report(
    tmp_path, monkeypatch, failure
):
    import json

    import httpx

    from avchain.scripts import run_incident_demo

    async def fail_capability(self):
        if failure == "timeout":
            raise TimeoutError("metadata deadline")
        if failure == "http":
            request = httpx.Request("GET", "http://127.0.0.1:1234/api/v1/models")
            httpx.Response(401, request=request).raise_for_status()
        raise ValueError("model does not advertise reasoning-off support")

    async def lab_before_inference(root, triage, **kwargs):
        await triage.model.analyze_incident("owned test fixture")
        pytest.fail("A failed capability check must not reach containment")

    report = tmp_path / "result.json"
    monkeypatch.setattr(
        run_incident_demo.LocalIncidentModel,
        "_check_reasoning_capability",
        fail_capability,
    )
    monkeypatch.setattr(run_incident_demo, "run_lab", lab_before_inference)
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_incident_demo",
            "--mode",
            "local_llm",
            "--model",
            "test-only",
            "--reasoning",
            "off",
            "--max-tokens",
            "3072",
            "--output",
            str(report),
        ],
    )
    assert run_incident_demo.main() == 2
    result = json.loads(report.read_text())
    assert result["status"] == "blocked_or_inconclusive"
    assert result["fallback_used"] is False
    assert result["model_http_responses"] == 0
    assert result["validated_model_outputs"] == 0
    assert result["model_request_diagnostics"] == []
    assert result["model_configuration"]["reasoning_effort"] == "none"
    assert result["model_reasoning_capability"] is None


@pytest.mark.parametrize("mode,reasoning", [("rules", "off"), ("local_llm", "low")])
def test_cli_rejects_invalid_reasoning_before_creating_lab(
    tmp_path, monkeypatch, mode, reasoning
):
    from avchain.scripts import run_incident_demo

    def must_not_create_lab(*args, **kwargs):
        pytest.fail("Invalid reasoning configuration must not create a laboratory")

    monkeypatch.setattr(
        run_incident_demo.tempfile, "TemporaryDirectory", must_not_create_lab
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_incident_demo",
            "--mode",
            mode,
            "--model",
            "test-only",
            "--reasoning",
            reasoning,
            "--output",
            str(tmp_path / "absent.json"),
        ],
    )
    with pytest.raises(SystemExit) as error:
        run_incident_demo.main()
    assert error.value.code == 2
