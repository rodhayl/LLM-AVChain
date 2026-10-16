from __future__ import annotations

from pathlib import Path

import pytest

from avchain.endpoint.classifier import EndpointArtifactClassifier
from avchain.endpoint.policy import requires_manual_review
from avchain.endpoint.scanner import ArtifactScan
from avchain.llm.schemas import EndpointClassificationOutput


class EscalatingEndpointLLMClient:
    async def classify_endpoint_artifact(
        self,
        *,
        matched_observables: list[str],
        artifact_summary: str,
    ) -> EndpointClassificationOutput:
        _ = matched_observables, artifact_summary
        return EndpointClassificationOutput(
            verdict="malicious_simulant",
            severity="high",
            recommended_action="quarantine",
            explanation="Model suggests quarantine",
            confidence=0.91,
            behavior_tags=["behavior:powershell-download"],
        )


class InvalidEndpointLLMClient:
    async def classify_endpoint_artifact(
        self,
        *,
        matched_observables: list[str],
        artifact_summary: str,
    ) -> EndpointClassificationOutput:
        _ = matched_observables, artifact_summary
        raise ValueError("schema-invalid response")


@pytest.mark.asyncio
async def test_endpoint_classifier_never_exceeds_policy_action() -> None:
    classifier = EndpointArtifactClassifier(
        default_action="alert",
        llm_client=EscalatingEndpointLLMClient(),
    )

    decision = await classifier.classify(
        ArtifactScan(
            path=Path("package.json"),
            digest="abc",
            matched_observables=["behavior:powershell-download"],
            detection_kind="contextual",
            summary="Suspicious package script",
            metadata={},
        )
    )

    assert decision.recommended_action == "alert"


@pytest.mark.asyncio
async def test_endpoint_classifier_falls_back_on_invalid_llm_output() -> None:
    classifier = EndpointArtifactClassifier(
        default_action="simulate_quarantine",
        llm_client=InvalidEndpointLLMClient(),
    )

    decision = await classifier.classify(
        ArtifactScan(
            path=Path("package.json"),
            digest="abc",
            matched_observables=["behavior:postinstall"],
            detection_kind="contextual",
            summary="Suspicious package manifest",
            metadata={},
        )
    )

    assert decision.verdict == "suspicious_simulant"
    assert decision.recommended_action == "simulate_quarantine"


def test_requires_manual_review_identifies_high_impact_actions() -> None:
    assert requires_manual_review("quarantine") is True
    assert requires_manual_review("block_execution") is True
    assert requires_manual_review("alert") is False
