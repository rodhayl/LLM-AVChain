from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from avchain.models.enums import LifecycleState, ProposalAction


class EvidencePayload(BaseModel):
    content_type: str = "application/json"
    data: Any


class LifecycleEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    from_state: LifecycleState | None = None
    to_state: LifecycleState
    actor: str
    proposal_ids: list[str] = Field(default_factory=list)
    notes: str | None = None


class ThreatEntry(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    observables: list[str] = Field(min_length=1)
    evidence_digests: list[str] = Field(default_factory=list)
    state: LifecycleState = LifecycleState.SUSPECTED
    attack_techniques: list[str] | None = None
    tlp_label: str = "TLP:CLEAR"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    history: list[LifecycleEvent] = Field(default_factory=list)


class ThreatEntryCreate(BaseModel):
    observables: list[str] = Field(min_length=1)
    evidence: list[EvidencePayload] = Field(default_factory=list)
    attack_techniques: list[str] | None = None
    tlp_label: str = "TLP:CLEAR"


class StateTransition(BaseModel):
    from_state: LifecycleState
    to_state: LifecycleState
    actor: str
    proposal_ids: list[str] = Field(default_factory=list)
    notes: str | None = None


class FeedbackSubmission(BaseModel):
    digest: str


class EvidenceItem(BaseModel):
    digest: str
    entry_id: uuid.UUID
    content_type: str
    size: int
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvidenceUploadRequest(BaseModel):
    entry_id: uuid.UUID
    data: Any
    model_config = ConfigDict(extra="forbid")


class AnalysisProvenance(BaseModel):
    analysis_backend: str
    llm_provider: str | None = None
    llm_model: str | None = None
    prompt_name: str | None = None
    prompt_version: str | None = None


class Proposal(BaseModel):
    proposal_id: str
    entry_id: uuid.UUID
    validator_id: str
    action: ProposalAction
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    timestamp: datetime
    signature: str
    provenance: AnalysisProvenance | None = None


class Decision(BaseModel):
    decision_id: str
    entry_id: uuid.UUID
    action: ProposalAction
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    supporting_proposals: list[str] = Field(default_factory=list)
    notes: str | None = None


class CoverageReport(BaseModel):
    report_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    entry_id: uuid.UUID
    vendor: str
    detected: bool
    timestamp: datetime


class CoverageMetric(BaseModel):
    entry_id: uuid.UUID
    vendors_total: int
    vendors_detected: int
    coverage_ratio: float = Field(ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TelemetryEvent(BaseModel):
    observable: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class FeedbackRecord(BaseModel):
    feedback_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    entry_id: uuid.UUID
    hashed_identifiers: dict[str, str]
    action_taken: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    digest: str = ""
    detection_kind: str | None = None
    matched_observables: list[str] = Field(default_factory=list)
    provenance: AnalysisProvenance | None = None


class ReviewRequest(BaseModel):
    entry_id: uuid.UUID
    reason: str


class ReviewRecord(BaseModel):
    review_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    entry_id: uuid.UUID
    reason: str
    status: str = "open"
    requested_by: str
    assigned_to: str | None = None
    resolution_action: str | None = None
    resolution_notes: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReviewRecordCreate(BaseModel):
    entry_id: uuid.UUID
    reason: str
    requested_by: str = "analyst"
    assigned_to: str | None = None


class ReviewAssignment(BaseModel):
    assigned_to: str
    actor: str


class ReviewAction(BaseModel):
    action: str
    actor: str
    notes: str | None = None


class ReviewNote(BaseModel):
    note_id: int
    review_id: uuid.UUID
    author: str
    note: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReviewNoteCreate(BaseModel):
    author: str
    note: str


class EvidenceIntegrityRecord(BaseModel):
    digest: str
    content_type: str
    size: int
    file_present: bool
    digest_matches: bool


class StixExportSummary(BaseModel):
    bundle_id: str
    object_count: int
    attack_pattern_count: int
    relationship_count: int
    tlp_label: str


class ReviewerPacket(BaseModel):
    entry: ThreatEntry
    evidence_integrity: list[EvidenceIntegrityRecord]
    proposals: list[Proposal]
    decisions: list[Decision]
    feedback: list[FeedbackRecord]
    coverage_reports: list[CoverageReport]
    reviews: list[ReviewRecord]
    review_notes: list[ReviewNote]
    stix_summary: StixExportSummary
    proof_points: dict[str, bool]
