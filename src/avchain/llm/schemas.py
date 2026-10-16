from __future__ import annotations

from pydantic import BaseModel, Field

from avchain.models.enums import ProposalAction


class ValidatorAnalysisOutput(BaseModel):
    action: ProposalAction
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning_summary: str
    attack_techniques: list[str] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)


class EndpointClassificationOutput(BaseModel):
    verdict: str
    severity: str
    recommended_action: str
    explanation: str
    confidence: float = Field(ge=0.0, le=1.0)
    behavior_tags: list[str] = Field(default_factory=list)
