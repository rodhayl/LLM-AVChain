from __future__ import annotations

from avchain.endpoint.policy import (
    EndpointDecision,
    bounded_action,
    rule_based_decision,
)
from avchain.endpoint.scanner import ArtifactScan
from avchain.llm.client import EndpointLLMClient
from avchain.llm.prompts import get_endpoint_prompt
from avchain.models.schemas import AnalysisProvenance


class EndpointArtifactClassifier:
    def __init__(
        self,
        *,
        default_action: str,
        llm_client: EndpointLLMClient | None = None,
    ) -> None:
        self.default_action = default_action
        self.llm_client = llm_client
        self.last_provenance = AnalysisProvenance(
            analysis_backend="endpoint_rule_prefilter"
        )

    async def classify(self, scan: ArtifactScan) -> EndpointDecision:
        fallback = rule_based_decision(scan, default_action=self.default_action)
        if self.llm_client is None or scan.detection_kind != "contextual":
            self.last_provenance = AnalysisProvenance(
                analysis_backend="endpoint_rule_prefilter"
            )
            return fallback
        try:
            llm_output = await self.llm_client.classify_endpoint_artifact(
                matched_observables=scan.matched_observables,
                artifact_summary=scan.summary,
            )
        except (RuntimeError, ValueError):
            self.last_provenance = AnalysisProvenance(
                analysis_backend="endpoint_rule_fallback",
                llm_provider="lmstudio",
                llm_model=getattr(self.llm_client, "endpoint_model", None),
                prompt_name=get_endpoint_prompt().name,
                prompt_version=get_endpoint_prompt().version,
            )
            return fallback
        self.last_provenance = AnalysisProvenance(
            analysis_backend="endpoint_llm_lmstudio",
            llm_provider="lmstudio",
            llm_model=getattr(self.llm_client, "endpoint_model", None),
            prompt_name=get_endpoint_prompt().name,
            prompt_version=get_endpoint_prompt().version,
        )
        return EndpointDecision(
            verdict=llm_output.verdict,
            severity=llm_output.severity,
            recommended_action=bounded_action(
                policy_action=fallback.recommended_action,
                requested_action=llm_output.recommended_action,
            ),
            explanation=llm_output.explanation,
            confidence=llm_output.confidence,
            behavior_tags=llm_output.behavior_tags or fallback.behavior_tags,
        )
