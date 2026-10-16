from __future__ import annotations

import hashlib
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def current_timestamp() -> datetime:
    return datetime.now(UTC)


def iso_now() -> str:
    return current_timestamp().isoformat()


def ensure_directory(path: str | Path) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )


def derive_proposal_id(entry_id: str, validator_id: str, timestamp: datetime) -> str:
    raw = f"{entry_id}:{validator_id}:{timestamp.isoformat()}"
    return compute_sha256(raw.encode("utf-8"))[:16]


def hash_identifier(value: Any) -> str:
    return compute_sha256(str(value).encode("utf-8"))


def hash_identifiers(mapping: dict[str, Any]) -> dict[str, str]:
    return {key: hash_identifier(value) for key, value in mapping.items()}


def paginate(items: list[Any], limit: int, offset: int) -> list[Any]:
    return items[offset : offset + limit]


def sanitize_filename(name: str) -> str:
    return "".join(
        character
        for character in name
        if character.isalnum() or character in {"-", "_"}
    )


def setup_logging(service_name: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(service_name)
    if logger.handlers:
        logger.setLevel(level)
        return logger
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt=json.dumps(
                {
                    "ts": "%(asctime)s",
                    "level": "%(levelname)s",
                    "service": service_name,
                    "msg": "%(message)s",
                }
            )
        )
    )
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger
