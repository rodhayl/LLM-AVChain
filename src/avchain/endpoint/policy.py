from __future__ import annotations

from dataclasses import dataclass, field

from avchain.endpoint.scanner import ArtifactScan


@dataclass(slots=True)
class EndpointDecision:
    verdict: str
    severity: str
    recommended_action: str
    explanation: str
    confidence: float
    behavior_tags: list[str] = field(default_factory=list)


ACTION_ORDER = {
    "log": 0,
    "alert": 1,
    "simulate_quarantine": 2,
    "quarantine": 3,
    "block_execution": 4,
}
MANUAL_REVIEW_ACTIONS = {"quarantine", "block_execution"}


def rule_based_decision(
    scan: ArtifactScan,
    *,
    default_action: str,
) -> EndpointDecision:
    if scan.detection_kind == "direct":
        return EndpointDecision(
            verdict="malicious_simulant",
            severity="critical",
            recommended_action=default_action,
            explanation="Artifact digest matches a confirmed ledger observable",
            confidence=0.99,
            behavior_tags=["direct-match", *scan.matched_observables],
        )
    return EndpointDecision(
        verdict="suspicious_simulant",
        severity="high",
        recommended_action=default_action,
        explanation="Artifact matched contextual suspicious indicators",
        confidence=0.86,
        behavior_tags=list(scan.matched_observables),
    )


def bounded_action(
    *,
    policy_action: str,
    requested_action: str | None,
) -> str:
    normalized_policy = policy_action.lower()
    normalized_requested = (requested_action or normalized_policy).lower()
    policy_level = ACTION_ORDER.get(normalized_policy, ACTION_ORDER["log"])
    requested_level = ACTION_ORDER.get(normalized_requested, ACTION_ORDER["log"])
    if requested_level > policy_level:
        return normalized_policy
    if normalized_requested not in ACTION_ORDER:
        return normalized_policy
    return normalized_requested


def requires_manual_review(action: str) -> bool:
    return action.lower() in MANUAL_REVIEW_ACTIONS
