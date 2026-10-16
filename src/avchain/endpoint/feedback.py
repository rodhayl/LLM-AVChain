from __future__ import annotations

from uuid import UUID

from avchain.endpoint.policy import EndpointDecision
from avchain.endpoint.remediation import RemediationResult
from avchain.endpoint.scanner import ArtifactScan
from avchain.models.schemas import AnalysisProvenance, FeedbackRecord
from avchain.utils.helpers import hash_identifiers


def build_feedback_record(
    *,
    entry_id: UUID,
    scan: ArtifactScan,
    decision: EndpointDecision,
    remediation: RemediationResult,
    provenance: AnalysisProvenance | None = None,
) -> FeedbackRecord:
    hashed_identifiers = hash_identifiers(
        {
            "artifact_path": str(scan.path),
            "artifact_name": scan.path.name,
            "artifact_digest": scan.digest,
            "detection_kind": scan.detection_kind,
            "verdict": decision.verdict,
            "severity": decision.severity,
        }
    )
    return FeedbackRecord(
        entry_id=entry_id,
        hashed_identifiers=hashed_identifiers,
        action_taken=remediation.action_taken,
        detection_kind=scan.detection_kind,
        matched_observables=list(scan.matched_observables),
        provenance=provenance,
    )
