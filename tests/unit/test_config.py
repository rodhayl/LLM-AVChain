from __future__ import annotations

from pathlib import Path

import pytest

from avchain.config.settings import get_settings, reset_settings_cache


def test_settings_load_from_environment(test_environment: dict[str, str]) -> None:
    reset_settings_cache()
    settings = get_settings()
    assert settings.database_url == test_environment["DATABASE_URL"]
    assert (
        settings.validator_registry_path == test_environment["VALIDATOR_REGISTRY_PATH"]
    )
    assert settings.evidence_dir == test_environment["EVIDENCE_DIR"]
    assert Path(settings.validator_registry_path).exists()


def test_settings_default_validator_registry_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VALIDATOR_REGISTRY_PATH", raising=False)
    reset_settings_cache()
    settings = get_settings()
    assert settings.validator_registry_path == "runtime/validators.yaml"
