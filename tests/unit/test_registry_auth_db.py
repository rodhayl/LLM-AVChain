from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi import HTTPException

from avchain.auth.dependencies import _extract_bearer_token, build_api_key_dependency
from avchain.config.settings import reset_settings_cache
from avchain.consensus.registry import (
    ValidatorRegistry,
    get_registry,
    reset_registry_cache,
)
from avchain.database.core import (
    _prepare_sqlite_path,
    get_engine,
    reset_database_state,
    session_scope,
)
from avchain.models.orm import Entry


def test_auth_dependency_accepts_bearer_and_rejects_bad_tokens(
    test_environment: dict[str, str],
) -> None:
    _ = test_environment
    reset_settings_cache()

    dependency = build_api_key_dependency("ledger_api_key")
    assert _extract_bearer_token(None) is None
    assert _extract_bearer_token("Bearer token") == "token"
    assert _extract_bearer_token("raw-token") is None
    assert dependency("Bearer test-ledger-key") == "test-ledger-key"

    with pytest.raises(HTTPException) as exc_info:
        dependency("wrong-token")
    assert exc_info.value.status_code == 401


def test_validator_registry_loads_records_and_caches(
    test_environment: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = ValidatorRegistry(test_environment["VALIDATOR_REGISTRY_PATH"])
    assert registry.count == 3
    assert registry.is_registered("validator1")
    assert registry.get("validator2") is not None
    assert registry.majority_threshold() == 2

    missing = ValidatorRegistry(
        Path(test_environment["VALIDATOR_REGISTRY_PATH"]).with_name("missing.yaml")
    )
    assert missing.count == 0
    assert missing.get("validator1") is None

    reset_registry_cache()
    monkeypatch.setenv(
        "VALIDATOR_REGISTRY_PATH",
        test_environment["VALIDATOR_REGISTRY_PATH"],
    )
    cached = get_registry()
    assert cached is get_registry()
    reset_registry_cache()


def test_database_helpers_create_parent_dirs_and_rollback(tmp_path: Path) -> None:
    assert _prepare_sqlite_path("postgresql://example") == {}

    database_url = f"sqlite:///{(tmp_path / 'db' / 'ledger.db').as_posix()}"
    connect_args = _prepare_sqlite_path(database_url)
    assert connect_args == {"check_same_thread": False}
    assert (tmp_path / "db").exists()

    reset_database_state()


def test_init_db_adds_feedback_purpose_column_for_older_sqlite_files(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "legacy.db"
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE evidence_objects (
                digest VARCHAR(64) PRIMARY KEY,
                entry_id VARCHAR(36),
                content_type VARCHAR(128),
                size INTEGER,
                created_at DATETIME
            )
            """
        )
        connection.commit()
    finally:
        connection.close()

    reset_database_state()
    from avchain.database.core import init_db

    init_db(f"sqlite:///{db_path.as_posix()}")

    check_connection = sqlite3.connect(db_path)
    try:
        columns = {
            row[1]
            for row in check_connection.execute("PRAGMA table_info(evidence_objects)")
        }
    finally:
        check_connection.close()

    assert "purpose" in columns
    reset_database_state()
    init_url = f"sqlite:///{(tmp_path / 'runtime' / 'ledger.db').as_posix()}"
    from avchain.database.core import init_db

    init_db(init_url)
    assert get_engine() is not None

    with pytest.raises(RuntimeError), session_scope() as db:
        db.add(
            Entry(
                observables_json='["ioc-1"]',
                state="suspected",
                tlp_label="TLP:CLEAR",
            )
        )
        raise RuntimeError("force rollback")

    with session_scope() as db:
        assert db.query(Entry).count() == 0

    reset_database_state()
