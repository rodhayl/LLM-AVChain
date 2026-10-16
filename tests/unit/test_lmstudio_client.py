from __future__ import annotations

import json

import httpx
import pytest

from avchain.llm.guardrails import parse_json_payload
from avchain.llm.providers.lmstudio import LMStudioClient
from avchain.models.enums import ProposalAction


@pytest.mark.asyncio
async def test_lmstudio_client_parses_validator_response() -> None:
    captured: dict[str, object] = {}
    response_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "action": ProposalAction.PROMOTE.value,
                            "confidence": 0.91,
                            "reasoning_summary": "Strong evidence alignment",
                            "attack_techniques": ["T1059"],
                            "evidence_gaps": [],
                        }
                    )
                }
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode("utf-8")
        return httpx.Response(200, json=response_payload, request=request)

    client = LMStudioClient(transport=httpx.MockTransport(handler))

    result = await client.analyze_validator_evidence(
        observables=["ioc-1"],
        evidence_summaries=["malicious powershell observed"],
    )

    assert result.action == ProposalAction.PROMOTE
    assert result.confidence == 0.91
    assert result.attack_techniques == ["T1059"]
    assert "Prompt version: v1." in str(captured["body"])


def test_parse_json_payload_rejects_non_object() -> None:
    with pytest.raises(ValueError):
        parse_json_payload('["not-an-object"]')
