"""Transport doubles verify the contract only; no actual model is called."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from avchain.incident.models import TriageResult
from avchain.incident.triage import LocalIncidentModel
from avchain.llm.providers.lmstudio import LMStudioClient


def metadata(options=None, *, instance="loaded-test"):
    return {
        "models": [
            {
                "type": "llm",
                "loaded_instances": [{"id": instance}],
                "capabilities": {
                    "reasoning": {
                        "allowed_options": ["off", "on"] if options is None else options
                    }
                },
            }
        ]
    }


def completion(tokens=0, *, reasoning="", finish="stop"):
    return {
        "choices": [
            {
                "finish_reason": finish,
                "message": {
                    "content": TriageResult(
                        verdict="uncertain", explanation="Test only", evidence_ids=[]
                    ).model_dump_json(),
                    "reasoning_content": reasoning,
                },
            }
        ],
        "usage": {"completion_tokens_details": {"reasoning_tokens": tokens}},
    }


def local_model(handler, **kwargs):
    return LocalIncidentModel(
        LMStudioClient(
            endpoint_model="loaded-test",
            base_url="http://127.0.0.1:1234/v1",
            max_retries=0,
            transport=httpx.MockTransport(handler),
            **kwargs,
        ),
        max_tokens=3072,
        reasoning="off",
    )


@pytest.mark.asyncio
async def test_off_uses_off_capability_but_none_wire_value_and_keeps_controls():
    calls = []

    def handler(request):
        calls.append(request)
        if request.method == "GET":
            assert str(request.url) == "http://127.0.0.1:1234/api/v1/models"
            return httpx.Response(200, json=metadata())
        assert str(request.url) == "http://127.0.0.1:1234/v1/chat/completions"
        body = json.loads(request.content)
        assert body["reasoning_effort"] == "none"
        assert body["max_tokens"] == 3072
        assert body["temperature"] == 0
        assert body["model"] == "loaded-test"
        assert body["response_format"]["json_schema"]["strict"] is True
        assert set(body) == {
            "model",
            "messages",
            "temperature",
            "response_format",
            "max_tokens",
            "reasoning_effort",
        }
        return httpx.Response(200, json=completion())

    model = local_model(handler)
    await model.analyze_incident("owned fixture")
    await model.analyze_incident("owned second fixture")
    assert [r.method for r in calls] == ["GET", "POST", "POST"]
    assert model.responses_received == 2
    assert model.reasoning_capability["off_supported"] is True
    assert all(
        d["reasoning_observation"] == "zero_reasoning_reported"
        and d["structured_output_validated"] is True
        and d["reasoning_effort"] == "none"
        for d in model.request_diagnostics
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        {},
        {"models": None},
        {"models": []},
        {"models": [None]},
        metadata(["on"]),
        metadata("off"),
        metadata(instance="other"),
        {"models": metadata()["models"] * 2},
        {
            "models": [
                {"type": "embedding", "loaded_instances": [{"id": "loaded-test"}]}
            ]
        },
        {"models": [{"type": "llm", "loaded_instances": [None]}]},
        {"models": [{"type": "llm", "loaded_instances": [{"id": "loaded-test"}]}]},
    ],
)
async def test_missing_or_ambiguous_capability_fails_before_inference(body):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=body)

    model = local_model(handler)
    with pytest.raises(ValueError):
        await model.analyze_incident("owned fixture")
    assert [r.method for r in calls] == ["GET"]
    assert model.responses_received == 0
    assert model.client.completion_responses_received == 0
    assert model.request_diagnostics == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tokens", "text", "observation"),
    [
        (1, "", "reasoning_observed"),
        (3069, "", "reasoning_observed"),
        (0, "private model text", "reasoning_observed"),
        (None, "", "unknown"),
        (-1, "", "unknown"),
        (True, "", "unknown"),
        ("0", "", "unknown"),
    ],
)
async def test_off_must_be_observed_not_inferred_and_never_retries(
    tokens, text, observation
):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            json=metadata()
            if request.method == "GET"
            else completion(tokens, reasoning=text),
        )

    model = local_model(handler)
    with pytest.raises(ValueError, match="not verified"):
        await model.analyze_incident("owned fixture")
    assert [r.method for r in calls] == ["GET", "POST"]
    assert model.responses_received == 0
    assert model.client.completion_responses_received == 1
    assert model.request_diagnostics[0]["reasoning_observation"] == observation
    assert model.request_diagnostics[0]["structured_output_validated"] is False
    assert "private model text" not in json.dumps(model.request_diagnostics)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["http", "length", "json"])
async def test_off_rejected_or_truncated_request_has_no_retry_or_fallback(failure):
    calls = []

    def handler(request):
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=metadata())
        if failure == "http":
            return httpx.Response(400, json={"error": "unsupported setting"})
        if failure == "json":
            return httpx.Response(200, text="invalid")
        return httpx.Response(200, json=completion(3069, finish="length"))

    model = local_model(handler)
    with pytest.raises(RuntimeError):
        await model.analyze_incident("owned fixture")
    assert [r.method for r in calls] == ["GET", "POST"]
    assert model.responses_received == 0
    assert model.request_diagnostics[0]["structured_output_validated"] is False
    assert model.request_diagnostics[0]["reasoning_observation"] == (
        "reasoning_observed" if failure == "length" else "unknown"
    )


@pytest.mark.asyncio
async def test_capability_timeout_is_bounded_without_inference_or_retry():
    calls = []

    async def handler(request):
        calls.append(request)
        await asyncio.sleep(1)
        return httpx.Response(200, json=metadata())

    model = local_model(handler, timeout_seconds=0.01)
    with pytest.raises(TimeoutError):
        await model.analyze_incident("owned fixture")
    assert [r.method for r in calls] == ["GET"]
    assert model.responses_received == 0


def test_reasoning_mode_requires_valid_value_and_zero_retries():
    with pytest.raises(ValueError, match="server_default or off"):
        LocalIncidentModel(LMStudioClient(max_retries=0), reasoning="low")
    with pytest.raises(ValueError, match="zero retries"):
        LocalIncidentModel(LMStudioClient(max_retries=1), reasoning="off")


@pytest.mark.asyncio
async def test_transport_rejects_wrong_wire_value_before_network():
    def handler(request):
        pytest.fail("Invalid wire setting must not make a request")

    client = LMStudioClient(transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="Only an explicit"):
        await client._complete_json(
            model="test",
            system_prompt="test",
            user_prompt="test",
            reasoning_effort="off",
        )
