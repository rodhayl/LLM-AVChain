from __future__ import annotations

import json
from typing import Any


def enforce_prompt_size(value: str, max_chars: int = 12000) -> str:
    if len(value) > max_chars:
        raise ValueError("Prompt payload exceeds maximum supported length")
    return value


def parse_json_payload(raw_content: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise ValueError("Model response was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("Model response JSON must be an object")
    return payload
