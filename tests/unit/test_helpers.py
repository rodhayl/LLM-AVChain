from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path

from avchain.utils.helpers import (
    canonical_json_bytes,
    compute_sha256,
    current_timestamp,
    ensure_directory,
    hash_identifier,
    hash_identifiers,
    iso_now,
    paginate,
    sanitize_filename,
    setup_logging,
)


def test_helper_utilities_cover_common_transformations(tmp_path: Path) -> None:
    created_dir = ensure_directory(tmp_path / "nested" / "path")
    assert created_dir.exists()
    assert created_dir == tmp_path / "nested" / "path"

    payload = {"b": 1, "a": {"z": 2}}
    encoded = canonical_json_bytes(payload)
    assert encoded == json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

    assert compute_sha256(b"hello") == hash_identifier("hello")
    assert hash_identifiers({"path": "C:/Temp/a.bin"})["path"] == hash_identifier(
        "C:/Temp/a.bin"
    )
    assert paginate([1, 2, 3, 4], limit=2, offset=1) == [2, 3]
    assert sanitize_filename("bad:/na*me?.txt") == "badnametxt"
    assert current_timestamp().tzinfo is not None
    assert iso_now().endswith("+00:00")


def test_setup_logging_reuses_existing_logger_handlers(capsys) -> None:
    service_name = f"svc-{uuid.uuid4()}"
    logger = setup_logging(service_name)
    handler_count = len(logger.handlers)
    logger.info("hello")
    captured = capsys.readouterr()
    assert '"service": "' + service_name + '"' in captured.out

    same_logger = setup_logging(service_name, level=logging.DEBUG)
    assert same_logger is logger
    assert len(same_logger.handlers) == handler_count
    assert same_logger.level == logging.DEBUG
