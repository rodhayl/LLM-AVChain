from __future__ import annotations

from collections.abc import Awaitable
from typing import Protocol

from avchain.config.settings import get_settings
from avchain.llm.client import ValidatorLLMClient
from avchain.llm.prompts import get_validator_prompt
from avchain.llm.registry import get_validator_llm_client
from avchain.models.enums import ProposalAction
from avchain.models.schemas import AnalysisProvenance

StrategyResult = tuple[ProposalAction, float, str]


class AnalysisStrategy(Protocol):
    def analyze(
        self,
        observables: list[str],
        evidence_data: list[bytes],
    ) -> StrategyResult | Awaitable[StrategyResult]: ...


class DeterministicHeuristic:
    MALICIOUS_SUFFIXES = {"a", "e", "f", "0"}
    MALICIOUS_MARKERS = (b"malicious", b"packed", b"powershell")

    def __init__(self) -> None:
        self.last_provenance = AnalysisProvenance(
            analysis_backend="deterministic_heuristic"
        )

    def analyze(
        self,
        observables: list[str],
        evidence_data: list[bytes],
    ) -> tuple[ProposalAction, float, str]:
        self.last_provenance = AnalysisProvenance(
            analysis_backend="deterministic_heuristic"
        )
        if not observables:
            return (
                ProposalAction.RETAIN,
                0.25,
                "No observables available for analysis",
            )

        score = 0.25
        primary_observable = observables[0]
        if primary_observable[-1].lower() in self.MALICIOUS_SUFFIXES:
            score += 0.45

        score += min(len(evidence_data), 2) * 0.1
        if any(
            marker in payload.lower()
            for payload in evidence_data
            for marker in self.MALICIOUS_MARKERS
        ):
            score += 0.2

        score = min(score, 0.95)
        if score >= 0.75:
            return (
                ProposalAction.PROMOTE,
                score,
                (
                    "Observable characteristics and evidence completeness meet the "
                    "promotion threshold"
                ),
            )
        if score <= 0.35:
            return (
                ProposalAction.DEPRECATE,
                score,
                "Evidence quality is too weak to retain the entry",
            )
        return (
            ProposalAction.RETAIN,
            score,
            "Signal is inconclusive; retain the current lifecycle state",
        )


class LMStudioAnalysisStrategy:
    def __init__(self, client: ValidatorLLMClient | None = None) -> None:
        self.client = client if client is not None else get_validator_llm_client()
        self.fallback = DeterministicHeuristic()
        self.last_provenance = AnalysisProvenance(
            analysis_backend="llm_lmstudio",
            llm_provider="lmstudio",
            llm_model=get_settings().lmstudio_model_validator,
            prompt_name=get_validator_prompt().name,
            prompt_version=get_validator_prompt().version,
        )

    async def analyze(
        self,
        observables: list[str],
        evidence_data: list[bytes],
    ) -> StrategyResult:
        if self.client is None:
            self.last_provenance = AnalysisProvenance(
                analysis_backend="heuristic_fallback"
            )
            return self.fallback.analyze(observables, evidence_data)
        try:
            response = await self.client.analyze_validator_evidence(
                observables=observables,
                evidence_summaries=[
                    _summarize_payload(payload) for payload in evidence_data
                ],
            )
        except (RuntimeError, ValueError):
            self.last_provenance = AnalysisProvenance(
                analysis_backend="heuristic_fallback",
                llm_provider="lmstudio",
                llm_model=get_settings().lmstudio_model_validator,
                prompt_name=get_validator_prompt().name,
                prompt_version=get_validator_prompt().version,
            )
            return self.fallback.analyze(observables, evidence_data)
        self.last_provenance = AnalysisProvenance(
            analysis_backend="llm_lmstudio",
            llm_provider="lmstudio",
            llm_model=get_settings().lmstudio_model_validator,
            prompt_name=get_validator_prompt().name,
            prompt_version=get_validator_prompt().version,
        )
        return (
            response.action,
            response.confidence,
            response.reasoning_summary,
        )


def _summarize_payload(payload: bytes) -> str:
    text = payload.decode("utf-8", errors="ignore").strip()
    if not text:
        return f"binary-payload:{len(payload)}"
    return text[:500]
