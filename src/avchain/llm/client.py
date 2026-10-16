from __future__ import annotations

from typing import Protocol

from avchain.llm.schemas import EndpointClassificationOutput, ValidatorAnalysisOutput


class ValidatorLLMClient(Protocol):
    async def analyze_validator_evidence(
        self,
        *,
        observables: list[str],
        evidence_summaries: list[str],
    ) -> ValidatorAnalysisOutput: ...


class EndpointLLMClient(Protocol):
    async def classify_endpoint_artifact(
        self,
        *,
        matched_observables: list[str],
        artifact_summary: str,
    ) -> EndpointClassificationOutput: ...
