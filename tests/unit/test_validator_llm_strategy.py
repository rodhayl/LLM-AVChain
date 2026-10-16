from __future__ import annotations

import pytest

from avchain.models.enums import ProposalAction
from avchain.validator.heuristics import LMStudioAnalysisStrategy


class InvalidValidatorLLMClient:
    async def analyze_validator_evidence(
        self,
        *,
        observables: list[str],
        evidence_summaries: list[str],
    ) -> object:
        _ = observables, evidence_summaries
        raise ValueError("schema-invalid response")


@pytest.mark.asyncio
async def test_validator_strategy_falls_back_on_invalid_llm_output() -> None:
    strategy = LMStudioAnalysisStrategy(client=InvalidValidatorLLMClient())

    action, confidence, explanation = await strategy.analyze(
        observables=["ioc-a"],
        evidence_data=[b"malicious powershell observed"],
    )

    assert action == ProposalAction.PROMOTE
    assert confidence >= 0.75
    assert "promotion threshold" in explanation.lower()
