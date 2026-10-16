from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from avchain.config.settings import get_settings
from avchain.utils.helpers import current_timestamp, ensure_directory


def runtime_dir() -> Path:
    registry_path = Path(get_settings().validator_registry_path)
    return ensure_directory(registry_path.parent or Path("runtime"))


def logs_dir() -> Path:
    return ensure_directory(runtime_dir() / "logs")


def status_dir() -> Path:
    return ensure_directory(runtime_dir() / "status")


def log_path(name: str) -> Path:
    return logs_dir() / f"{name}.log"


def status_path(name: str) -> Path:
    return status_dir() / f"{name}.json"


class StatusPublicationError(OSError):
    """No new status was published; the previous target remains untouched."""


def write_status(name: str, payload: dict[str, Any]) -> Path:
    full_payload = {
        **payload,
        "pid": os.getpid(),
        "last_heartbeat": current_timestamp().isoformat(),
    }
    target = status_path(name)
    serialized = json.dumps(full_payload, sort_keys=True, indent=2)
    last_error: OSError | None = None
    for attempt in range(5):
        temp_target = target.with_name(f"{target.stem}.{uuid.uuid4().hex}.tmp")
        try:
            temp_target.write_text(serialized, encoding="utf-8")
            temp_target.replace(target)
            return target
        except OSError as exc:
            last_error = exc
        finally:
            with suppress(OSError):
                temp_target.unlink(missing_ok=True)
        if attempt < 4:
            time.sleep(0.05)
    raise StatusPublicationError(
        f"Could not atomically publish status {name!r} after 5 attempts: {last_error}"
    ) from last_error


def read_status(name: str) -> dict[str, Any] | None:
    target = status_path(name)
    if not target.exists():
        return None
    try:
        return cast(dict[str, Any], json.loads(target.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return None


def parse_heartbeat(payload: dict[str, Any]) -> datetime | None:
    heartbeat = payload.get("last_heartbeat")
    if not isinstance(heartbeat, str):
        return None
    try:
        heartbeat_dt = datetime.fromisoformat(heartbeat)
    except ValueError:
        return None
    if heartbeat_dt.tzinfo is None:
        heartbeat_dt = heartbeat_dt.replace(tzinfo=UTC)
    return heartbeat_dt


def heartbeat_age_seconds(
    payload: dict[str, Any],
    *,
    now: datetime | None = None,
) -> float | None:
    heartbeat_dt = parse_heartbeat(payload)
    if heartbeat_dt is None:
        return None
    observed_now = now or current_timestamp()
    if observed_now.tzinfo is None:
        observed_now = observed_now.replace(tzinfo=UTC)
    return max((observed_now - heartbeat_dt).total_seconds(), 0.0)


def is_status_fresh(
    payload: dict[str, Any],
    *,
    freshness_seconds: float = 30.0,
    now: datetime | None = None,
) -> bool:
    age_seconds = heartbeat_age_seconds(payload, now=now)
    if age_seconds is None:
        return False
    return age_seconds <= freshness_seconds


def list_status_payloads(
    *,
    freshness_seconds: float = 30.0,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    observed_now = now or current_timestamp()
    statuses: list[dict[str, Any]] = []
    for path in sorted(status_dir().glob("*.json")):
        payload = read_status(path.stem)
        if payload is None:
            continue
        age_seconds = heartbeat_age_seconds(payload, now=observed_now)
        statuses.append(
            {
                "name": path.stem,
                "fresh": is_status_fresh(
                    payload,
                    freshness_seconds=freshness_seconds,
                    now=observed_now,
                ),
                "heartbeat_age_seconds": round(age_seconds, 3)
                if age_seconds is not None
                else None,
                **payload,
            }
        )
    return statuses
