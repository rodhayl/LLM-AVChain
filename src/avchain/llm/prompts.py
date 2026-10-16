from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PromptSpec:
    name: str
    version: str
    system_prompt: str


VALIDATOR_PROMPT = PromptSpec(
    name="validator_triage",
    version="v1",
    system_prompt=(
        "You are a bounded AVChain validator. Return only JSON with keys action, "
        "confidence, reasoning_summary, attack_techniques, evidence_gaps."
    ),
)

ENDPOINT_PROMPT = PromptSpec(
    name="endpoint_artifact_classification",
    version="v1",
    system_prompt=(
        "You are a bounded AVChain endpoint classifier. Return only JSON with keys "
        "verdict, severity, recommended_action, explanation, confidence, "
        "behavior_tags."
    ),
)


def get_validator_prompt() -> PromptSpec:
    return VALIDATOR_PROMPT


def get_endpoint_prompt() -> PromptSpec:
    return ENDPOINT_PROMPT
