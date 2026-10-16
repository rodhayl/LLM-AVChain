from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from avchain.models.orm import Base

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _prepare_sqlite_path(database_url: str) -> dict[str, bool]:
    if not database_url.startswith("sqlite"):
        return {}
    if database_url.startswith("sqlite:///"):
        db_path = Path(database_url.replace("sqlite:///", "", 1))
        db_path.parent.mkdir(parents=True, exist_ok=True)
    return {"check_same_thread": False}


def _configure_sqlite(dbapi_connection: Any, _: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_engine_from_url(database_url: str) -> Engine:
    connect_args = _prepare_sqlite_path(database_url)
    engine = create_engine(
        database_url,
        connect_args=connect_args,
        future=True,
    )
    if database_url.startswith("sqlite"):
        event.listen(engine, "connect", _configure_sqlite)
    return engine


def init_db(database_url: str | None = None) -> None:
    from avchain.config.settings import get_settings

    resolved_url = database_url or get_settings().database_url
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = create_engine_from_url(resolved_url)
    Base.metadata.create_all(_engine)
    _apply_compat_migrations(_engine)
    _session_factory = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


def reset_database_state() -> None:
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None


def _apply_compat_migrations(engine: Engine) -> None:
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    if "evidence_objects" not in table_names:
        return
    evidence_columns = {
        column["name"] for column in inspector.get_columns("evidence_objects")
    }
    if "purpose" not in evidence_columns:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE evidence_objects "
                    "ADD COLUMN purpose VARCHAR(32) NOT NULL DEFAULT 'supporting'"
                )
            )
    if "proposals" in table_names:
        proposal_columns = {
            column["name"] for column in inspector.get_columns("proposals")
        }
        column_specs = {
            "analysis_backend": "VARCHAR(64)",
            "llm_provider": "VARCHAR(64)",
            "llm_model": "VARCHAR(128)",
            "prompt_name": "VARCHAR(128)",
            "prompt_version": "VARCHAR(32)",
        }
        missing_columns = [
            (name, ddl)
            for name, ddl in column_specs.items()
            if name not in proposal_columns
        ]
        if missing_columns:
            with engine.begin() as connection:
                for column_name, ddl in missing_columns:
                    connection.execute(
                        text(f"ALTER TABLE proposals ADD COLUMN {column_name} {ddl}")
                    )
    if "entry_feedback" in table_names:
        feedback_columns = {
            column["name"] for column in inspector.get_columns("entry_feedback")
        }
        feedback_specs = {
            "action_taken": "VARCHAR(64)",
            "detection_kind": "VARCHAR(32)",
            "matched_observables_json": "TEXT",
            "analysis_backend": "VARCHAR(64)",
            "llm_provider": "VARCHAR(64)",
            "llm_model": "VARCHAR(128)",
            "prompt_name": "VARCHAR(128)",
            "prompt_version": "VARCHAR(32)",
            "endpoint_id": "VARCHAR(128)",
            "endpoint_signature_valid": "BOOLEAN",
        }
        missing_feedback_columns = [
            (name, ddl)
            for name, ddl in feedback_specs.items()
            if name not in feedback_columns
        ]
        if missing_feedback_columns:
            with engine.begin() as connection:
                for column_name, ddl in missing_feedback_columns:
                    connection.execute(
                        text(
                            f"ALTER TABLE entry_feedback ADD COLUMN {column_name} {ddl}"
                        )
                    )
    if "review_records" in table_names and "review_notes" not in table_names:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE review_notes ("
                    "note_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "review_id VARCHAR(36) NOT NULL "
                    "REFERENCES review_records(review_id), "
                    "author VARCHAR(64) NOT NULL, "
                    "note TEXT NOT NULL, "
                    "created_at DATETIME NOT NULL"
                    ")"
                )
            )


def get_engine() -> Engine:
    if _engine is None:
        init_db()
    assert _engine is not None
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    if _session_factory is None:
        init_db()
    assert _session_factory is not None
    return _session_factory


def get_session() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
