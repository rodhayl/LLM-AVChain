from __future__ import annotations

import asyncio
from time import monotonic
from typing import Any, Literal

import httpx

from avchain.config.settings import get_settings
from avchain.llm.guardrails import enforce_prompt_size, parse_json_payload
from avchain.llm.prompts import get_endpoint_prompt, get_validator_prompt
from avchain.llm.schemas import EndpointClassificationOutput, ValidatorAnalysisOutput


class LMStudioClient:
    def __init__(
        self,
        *,
        base_url: str | None = None,
        validator_model: str | None = None,
        endpoint_model: str | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
        json_mode: bool | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        settings = get_settings()
        self.base_url = base_url or settings.lmstudio_base_url
        self.validator_model = validator_model or settings.lmstudio_model_validator
        self.endpoint_model = endpoint_model or settings.lmstudio_model_endpoint
        self.timeout_seconds = timeout_seconds or settings.lmstudio_timeout_seconds
        self.max_retries = (
            max_retries if max_retries is not None else settings.lmstudio_max_retries
        )
        self.json_mode = settings.llm_json_mode if json_mode is None else json_mode
        self._transport = transport
        self.completion_responses_received = 0
        self.last_completion_diagnostics: dict[str, Any] | None = None

    async def analyze_validator_evidence(
        self,
        *,
        observables: list[str],
        evidence_summaries: list[str],
    ) -> ValidatorAnalysisOutput:
        prompt = get_validator_prompt()
        payload = await self._complete_json(
            model=self.validator_model,
            system_prompt=f"{prompt.system_prompt} Prompt version: {prompt.version}.",
            user_prompt=enforce_prompt_size(
                "\n".join(
                    [
                        f"observables={observables!r}",
                        f"evidence_summaries={evidence_summaries!r}",
                    ]
                )
            ),
        )
        return ValidatorAnalysisOutput.model_validate(payload)

    async def classify_endpoint_artifact(
        self,
        *,
        matched_observables: list[str],
        artifact_summary: str,
    ) -> EndpointClassificationOutput:
        prompt = get_endpoint_prompt()
        payload = await self._complete_json(
            model=self.endpoint_model,
            system_prompt=f"{prompt.system_prompt} Prompt version: {prompt.version}.",
            user_prompt=enforce_prompt_size(
                "\n".join(
                    [
                        f"matched_observables={matched_observables!r}",
                        f"artifact_summary={artifact_summary}",
                    ]
                )
            ),
        )
        return EndpointClassificationOutput.model_validate(payload)

    async def _complete_json(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        json_schema: dict[str, Any] | None = None,
        max_tokens: int | None = None,
        reasoning_effort: Literal["none"] | None = None,
    ) -> dict[str, Any]:
        if reasoning_effort not in (None, "none"):
            raise ValueError("Only an explicit reasoning_effort='none' is supported")
        request_payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
        }
        if reasoning_effort is not None:
            request_payload["reasoning_effort"] = reasoning_effort
        if json_schema is not None:
            request_payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "incident_triage",
                    "strict": True,
                    "schema": json_schema,
                },
            }
        elif self.json_mode:
            request_payload["response_format"] = {"type": "json_object"}
        if max_tokens is not None:
            if type(max_tokens) is not int or not 1 <= max_tokens <= 4096:
                raise ValueError("Completion token limit must be between 1 and 4096")
            request_payload["max_tokens"] = max_tokens

        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            transport=self._transport,
            trust_env=False,
        ) as client:
            last_error: Exception | None = None
            for _ in range(self.max_retries + 1):
                try:
                    started = monotonic()
                    diagnostics: dict[str, Any] = {
                        "max_tokens": max_tokens,
                        "timeout_seconds": self.timeout_seconds,
                        "prompt_utf8_bytes": len(
                            (system_prompt + user_prompt).encode("utf-8")
                        ),
                        "http_status": None,
                        "finish_reason": None,
                        "usage": {},
                        "content_utf8_bytes": None,
                        "reasoning_utf8_bytes": {},
                    }
                    self.last_completion_diagnostics = diagnostics
                    if reasoning_effort is not None:
                        diagnostics["reasoning_effort"] = reasoning_effort
                    # httpx timeouts bound individual IO waits, not the total call.
                    async with asyncio.timeout(self.timeout_seconds):
                        response = await client.post(
                            "/chat/completions",
                            json=request_payload,
                        )
                    diagnostics["http_status"] = response.status_code
                    response.raise_for_status()
                    self.completion_responses_received += 1
                    body = response.json()
                    if not isinstance(body, dict):
                        raise ValueError("Model response must be an object")
                    usage = body.get("usage")
                    if isinstance(usage, dict):
                        for key in (
                            "prompt_tokens",
                            "completion_tokens",
                            "total_tokens",
                        ):
                            value = usage.get(key)
                            if type(value) is int and value >= 0:
                                diagnostics["usage"][key] = value
                        details = usage.get("completion_tokens_details")
                        if isinstance(details, dict):
                            value = details.get("reasoning_tokens")
                            if type(value) is int and value >= 0:
                                diagnostics["usage"]["reasoning_tokens"] = value
                    choices = body.get("choices")
                    if not isinstance(choices, list) or not choices:
                        raise ValueError("Model response has no completion choices")
                    choice = choices[0]
                    if not isinstance(choice, dict):
                        raise ValueError("Model completion choice must be an object")
                    finish_reason = choice.get("finish_reason")
                    diagnostics["finish_reason"] = (
                        finish_reason
                        if finish_reason
                        in (
                            "stop",
                            "length",
                            "tool_calls",
                            "content_filter",
                            "function_call",
                        )
                        else "unrecognized"
                        if finish_reason is not None
                        else None
                    )
                    message = choice.get("message")
                    if isinstance(message, dict):
                        content = message.get("content")
                        if isinstance(content, str):
                            diagnostics["content_utf8_bytes"] = len(
                                content.encode("utf-8")
                            )
                        for key in ("reasoning", "reasoning_content"):
                            value = message.get(key)
                            if isinstance(value, str):
                                diagnostics["reasoning_utf8_bytes"][key] = len(
                                    value.encode("utf-8")
                                )
                    if finish_reason == "length":
                        raise ValueError(
                            "Model response was truncated by its token limit"
                        )
                    raw_content = choice["message"]["content"]
                    if not isinstance(raw_content, str):
                        raise ValueError("Model completion content must be a string")
                    return parse_json_payload(raw_content)
                except (
                    httpx.HTTPError,
                    KeyError,
                    ValueError,
                    TypeError,
                    IndexError,
                    TimeoutError,
                ) as exc:
                    diagnostics["error_type"] = type(exc).__name__
                    last_error = exc
                finally:
                    diagnostics["elapsed_seconds"] = round(monotonic() - started, 3)
            if last_error is None:
                raise RuntimeError("LM Studio request failed without an exception")
            raise RuntimeError("LM Studio request failed") from last_error
