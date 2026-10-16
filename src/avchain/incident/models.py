from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

Digest = str
CheckedDigest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Operation = Literal["quarantine_file", "disable_npm_hook"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Artifact(Contract):
    artifact_id: str
    path_hash: str
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    excerpt: str = Field(max_length=8192)
    tags: list[str]
    # This is a structured fact from a manifest, never a command to execute.
    hook: str | None = None
    related_artifact_id: str | None = None


class Incident(Contract):
    schema_version: Literal[1] = 1
    incident_id: str
    observed_at: datetime
    artifacts: list[Artifact] = Field(max_length=128)
    limitations: list[str] = Field(default_factory=list)


class ActionTemplate(Contract):
    action_id: str = Field(pattern=r"^[a-z0-9_-]{1,64}$")
    operation: Operation
    required_tags: list[str] = Field(min_length=1, max_length=16)


class RemediationPackage(Contract):
    schema_version: Literal[1] = 1
    package_id: str = Field(pattern=r"^[a-z0-9_-]{1,64}$")
    version: int = Field(ge=1)
    entry_id: UUID
    title: str = Field(min_length=1, max_length=256)
    rationale: str = Field(min_length=1, max_length=2000)
    evidence_digests: list[str] = Field(min_length=1, max_length=32)
    issued_at: datetime
    expires_at: datetime
    actions: list[ActionTemplate] = Field(min_length=1, max_length=8)
    source_references: list[str] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def check_contract(self) -> RemediationPackage:
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Package timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("Invalid validity interval")
        if len({a.action_id for a in self.actions}) != len(self.actions):
            raise ValueError("Duplicate action identifier")
        for digest in self.evidence_digests:
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("Invalid evidence digest")
        return self


class ValidatorApproval(Contract):
    validator_id: str
    signature: str


class SignedPackage(Contract):
    package: RemediationPackage
    approvals: list[ValidatorApproval] = Field(min_length=1, max_length=32)


class PackageRevocation(Contract):
    schema_version: Literal[1] = 1
    package_id: str = Field(pattern=r"^[a-z0-9_-]{1,64}$")
    version: int = Field(ge=1)
    package_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason: str = Field(min_length=1, max_length=2000)
    timestamp: datetime


class SignedRevocation(Contract):
    revocation: PackageRevocation
    approvals: list[ValidatorApproval] = Field(min_length=1, max_length=32)


class ActionBinding(Contract):
    action_id: str
    artifact_id: str


class TriageResult(Contract):
    verdict: Literal["suspicious", "benign", "uncertain"]
    explanation: str = Field(max_length=2000)
    evidence_ids: list[str] = Field(max_length=128)
    inferences: list[str] = Field(default_factory=list, max_length=16)
    actions: list[ActionBinding] = Field(default_factory=list, max_length=16)


class AnalysisRecord(Contract):
    backend: Literal["rules", "local_llm", "test_double"]
    model: str | None = None
    prompt_version: str = "incident-v1"
    temperature: int = 0
    input_digest: str
    output: TriageResult


class TransferGrant(Contract):
    actor_artifact_id: CheckedDigest
    resource_artifact_id: CheckedDigest
    receiver: Literal["owned_loopback_receiver"] = "owned_loopback_receiver"


class TransferObservation(Contract):
    """Receiver evidence during a byte-verified owned replay; not a read trace."""

    actor_artifact_id: CheckedDigest
    actor_digest: CheckedDigest
    actor_path_hash: CheckedDigest
    source: Literal["owned_receiver_during_verified_replay"] = (
        "owned_receiver_during_verified_replay"
    )
    receiver: Literal["owned_loopback_receiver"] = "owned_loopback_receiver"
    received_payload_digests: list[CheckedDigest] = Field(min_length=1, max_length=8)


class TransferCaseContext(Contract):
    """One lab case's explicit permission and actual receipt, not a verdict."""

    kind: Literal["owned_canary_transfer"] = "owned_canary_transfer"
    schema_version: Literal[1] = 1
    lab_scope: Literal["artificial_data_loopback_only"] = (
        "artificial_data_loopback_only"
    )
    resource_artifact_id: CheckedDigest
    transfer_requires_grant: Literal[True] = True
    grant_records_complete: bool
    grants: list[TransferGrant] = Field(max_length=8)
    observation: TransferObservation | None


class SourceCase(Contract):
    """Digest-linked observation and decision, not proof of execution success."""

    kind: Literal["avchain-source-case"] = "avchain-source-case"
    schema_version: Literal[1] = 1
    incident_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    knowledge: RemediationPackage
    analysis: AnalysisRecord
    case_context: TransferCaseContext | None = None

    @model_validator(mode="after")
    def no_model_prose(self) -> SourceCase:
        if self.analysis.output.explanation or self.analysis.output.inferences:
            raise ValueError("Source cases must omit model prose and hypotheses")
        return self


class ExecutionReceipt(Contract):
    status: Literal["applied", "rolled_back", "rollback_incomplete", "blocked"]
    incident_id: str
    package_digest: str
    operations: list[dict[str, str]]
    explanation: str
