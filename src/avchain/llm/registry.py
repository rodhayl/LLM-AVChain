from __future__ import annotations

from avchain.config.settings import get_settings
from avchain.llm.providers import LMStudioClient


def get_validator_llm_client() -> LMStudioClient | None:
    if get_settings().llm_provider.lower() != "lmstudio":
        return None
    return LMStudioClient()


def get_endpoint_llm_client() -> LMStudioClient | None:
    if get_settings().llm_provider.lower() != "lmstudio":
        return None
    return LMStudioClient()
