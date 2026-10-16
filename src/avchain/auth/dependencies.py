from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from avchain.config.settings import get_settings

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)
AuthorizationHeader = Annotated[str | None, Security(api_key_header)]


def _extract_bearer_token(header_value: str | None) -> str | None:
    if header_value is None:
        return None
    if header_value.startswith("Bearer "):
        return header_value.removeprefix("Bearer ")
    return None


def build_api_key_dependency(setting_name: str) -> Callable[[AuthorizationHeader], str]:
    def dependency(api_key: AuthorizationHeader) -> str:
        expected = getattr(get_settings(), setting_name, None)
        token = _extract_bearer_token(api_key)
        if token is None or expected is None or token != expected:
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
        return token

    return dependency


require_ledger_key = build_api_key_dependency("ledger_api_key")
require_evidence_key = build_api_key_dependency("evidence_api_key")
require_consensus_key = build_api_key_dependency("consensus_api_key")
require_coverage_key = build_api_key_dependency("coverage_api_key")
require_agent_key = build_api_key_dependency("agent_api_key")
