from __future__ import annotations

from avchain.models.enums import LifecycleState, ProposalAction
from avchain.models.schemas import (
    AnalysisProvenance,
    CoverageMetric,
    CoverageReport,
    Decision,
    EvidenceIntegrityRecord,
    EvidenceItem,
    FeedbackRecord,
    FeedbackSubmission,
    LifecycleEvent,
    Proposal,
    ReviewAction,
    ReviewAssignment,
    ReviewerPacket,
    ReviewNote,
    ReviewNoteCreate,
    ReviewRecord,
    ReviewRecordCreate,
    ReviewRequest,
    StateTransition,
    StixExportSummary,
    TelemetryEvent,
    ThreatEntry,
    ThreatEntryCreate,
)


async def test_openapi_paths_match_api_contracts(
    ledger_client,
    evidence_client,
    consensus_client,
    coverage_client,
) -> None:
    ledger_paths = (await ledger_client.get("/openapi.json")).json()["paths"]
    evidence_paths = (await evidence_client.get("/openapi.json")).json()["paths"]
    consensus_paths = (await consensus_client.get("/openapi.json")).json()["paths"]
    coverage_paths = (await coverage_client.get("/openapi.json")).json()["paths"]

    assert {
        "/ledger/entries",
        "/ledger/entries/{entry_id}",
        "/ledger/entries/{entry_id}/reviewer_packet",
        "/ledger/entries/{entry_id}/transitions",
        "/ledger/entries/{entry_id}/feedback",
        "/ledger/entries/{entry_id}/stix",
        "/ledger/entries/{entry_id}/taxii/publish",
        "/stix/import",
        "/stix/import/preview",
        "/runtime/status",
        "/runtime/status/{name}",
        "/taxii/collections/{collection_id}/preview",
        "/taxii/collections/{collection_id}/import",
        "/review/records",
        "/review/records/{review_id}",
        "/review/records/{review_id}/context",
        "/review/records/{review_id}/notes",
        "/review/records/{review_id}/assign",
        "/review/records/{review_id}/actions",
        "/trust/endpoints",
        "/trust/endpoints/{endpoint_id}",
    }.issubset(ledger_paths)
    assert {"/evidence", "/evidence/{digest}", "/evidence/entries/{entry_id}"}.issubset(
        evidence_paths
    )
    assert {
        "/consensus/proposals",
        "/consensus/proposals/{entry_id}",
        "/consensus/review_requests",
        "/consensus/decisions/{entry_id}",
    }.issubset(consensus_paths)
    assert {"/coverage/reports", "/coverage/metrics/{entry_id}"}.issubset(
        coverage_paths
    )


async def test_authentication_is_enforced_on_all_services(
    ledger_client,
    evidence_client,
    consensus_client,
    coverage_client,
) -> None:
    assert (await ledger_client.get("/ledger/entries")).status_code == 401
    assert (await evidence_client.get("/evidence/missing")).status_code == 401
    assert (await consensus_client.get("/consensus/decisions/test")).status_code == 401
    assert (await coverage_client.get("/coverage/metrics/test")).status_code == 401


def test_domain_enums_match_spec() -> None:
    assert [item.value for item in LifecycleState] == [
        "suspected",
        "confirmed",
        "review",
        "deprecated",
    ]
    assert [item.value for item in ProposalAction] == [
        "promote",
        "retain",
        "review",
        "deprecate",
    ]


def test_schema_field_names_match_spec() -> None:
    assert set(ThreatEntry.model_fields) == {
        "id",
        "observables",
        "evidence_digests",
        "state",
        "attack_techniques",
        "tlp_label",
        "created_at",
        "updated_at",
        "history",
    }
    assert set(LifecycleEvent.model_fields) == {
        "timestamp",
        "from_state",
        "to_state",
        "actor",
        "proposal_ids",
        "notes",
    }
    assert set(EvidenceItem.model_fields) == {
        "digest",
        "entry_id",
        "content_type",
        "size",
        "created_at",
    }
    assert set(EvidenceIntegrityRecord.model_fields) == {
        "digest",
        "content_type",
        "size",
        "file_present",
        "digest_matches",
    }
    assert set(AnalysisProvenance.model_fields) == {
        "analysis_backend",
        "llm_provider",
        "llm_model",
        "prompt_name",
        "prompt_version",
    }
    assert set(Proposal.model_fields) == {
        "proposal_id",
        "entry_id",
        "validator_id",
        "action",
        "confidence",
        "explanation",
        "timestamp",
        "signature",
        "provenance",
    }
    assert set(Decision.model_fields) == {
        "decision_id",
        "entry_id",
        "action",
        "timestamp",
        "supporting_proposals",
        "notes",
    }
    assert set(CoverageReport.model_fields) == {
        "report_id",
        "entry_id",
        "vendor",
        "detected",
        "timestamp",
    }
    assert set(CoverageMetric.model_fields) == {
        "entry_id",
        "vendors_total",
        "vendors_detected",
        "coverage_ratio",
        "timestamp",
    }
    assert set(TelemetryEvent.model_fields) == {"observable", "metadata"}
    assert set(FeedbackRecord.model_fields) == {
        "feedback_id",
        "entry_id",
        "hashed_identifiers",
        "action_taken",
        "timestamp",
        "digest",
        "detection_kind",
        "matched_observables",
        "provenance",
    }
    assert set(ThreatEntryCreate.model_fields) == {
        "observables",
        "evidence",
        "attack_techniques",
        "tlp_label",
    }
    assert set(StateTransition.model_fields) == {
        "from_state",
        "to_state",
        "actor",
        "proposal_ids",
        "notes",
    }
    assert set(FeedbackSubmission.model_fields) == {"digest"}
    assert set(ReviewRequest.model_fields) == {"entry_id", "reason"}
    assert set(ReviewRecord.model_fields) == {
        "review_id",
        "entry_id",
        "reason",
        "status",
        "requested_by",
        "assigned_to",
        "resolution_action",
        "resolution_notes",
        "created_at",
        "updated_at",
    }
    assert set(ReviewRecordCreate.model_fields) == {
        "entry_id",
        "reason",
        "requested_by",
        "assigned_to",
    }
    assert set(ReviewAssignment.model_fields) == {"assigned_to", "actor"}
    assert set(ReviewAction.model_fields) == {"action", "actor", "notes"}
    assert set(ReviewNote.model_fields) == {
        "note_id",
        "review_id",
        "author",
        "note",
        "created_at",
    }
    assert set(ReviewNoteCreate.model_fields) == {"author", "note"}
    assert set(StixExportSummary.model_fields) == {
        "bundle_id",
        "object_count",
        "attack_pattern_count",
        "relationship_count",
        "tlp_label",
    }
    assert set(ReviewerPacket.model_fields) == {
        "entry",
        "evidence_integrity",
        "proposals",
        "decisions",
        "feedback",
        "coverage_reports",
        "reviews",
        "review_notes",
        "stix_summary",
        "proof_points",
    }
