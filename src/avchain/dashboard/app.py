from __future__ import annotations

import json
from typing import Any

import streamlit as st

from avchain.database.core import init_db, session_scope
from avchain.evidence.storage import EvidenceStorage
from avchain.models.orm import (
    CoverageReportORM,
    Decision,
    Entry,
    EntryEvent,
    EntryEvidenceLink,
    EntryFeedback,
    EvidenceObject,
    Proposal,
    ReviewRecordORM,
)
from avchain.models.schemas import ThreatEntry
from avchain.stix_taxii import build_stix_bundle
from avchain.utils.helpers import compute_sha256
from avchain.utils.runtime_status import list_status_payloads


def _entry_rows() -> list[dict[str, str]]:
    with session_scope() as db:
        entries = db.query(Entry).order_by(Entry.created_at.desc()).all()
        return [
            {
                "id": entry.id,
                "state": entry.state,
                "observables": ", ".join(json.loads(entry.observables_json)),
                "tlp": entry.tlp_label,
                "updated_at": entry.updated_at.isoformat(),
            }
            for entry in entries
        ]


def _event_rows() -> list[dict[str, str]]:
    with session_scope() as db:
        events = (
            db.query(EntryEvent).order_by(EntryEvent.timestamp.desc()).limit(20).all()
        )
        return [
            {
                "entry_id": event.entry_id,
                "from_state": event.from_state or "",
                "to_state": event.to_state,
                "actor": event.actor,
                "timestamp": event.timestamp.isoformat(),
                "notes": event.notes or "",
            }
            for event in events
        ]


def _proposal_rows() -> list[dict[str, str]]:
    with session_scope() as db:
        proposals = (
            db.query(Proposal).order_by(Proposal.timestamp.desc()).limit(20).all()
        )
        return [
            {
                "proposal_id": proposal.proposal_id,
                "entry_id": proposal.entry_id,
                "validator_id": proposal.validator_id,
                "action": proposal.action,
                "confidence": f"{proposal.confidence:.2f}",
                "backend": proposal.analysis_backend or "",
                "llm_model": proposal.llm_model or "",
                "prompt_version": proposal.prompt_version or "",
                "explanation": proposal.explanation,
                "timestamp": proposal.timestamp.isoformat(),
            }
            for proposal in proposals
        ]


def _decision_rows() -> list[dict[str, str]]:
    with session_scope() as db:
        decisions = (
            db.query(Decision).order_by(Decision.timestamp.desc()).limit(20).all()
        )
        return [
            {
                "decision_id": decision.decision_id,
                "entry_id": decision.entry_id,
                "action": decision.action,
                "supporting_proposals": ", ".join(
                    proposal.proposal_id for proposal in decision.proposals
                ),
                "timestamp": decision.timestamp.isoformat(),
                "notes": decision.notes or "",
            }
            for decision in decisions
        ]


def _feedback_rows() -> list[dict[str, str]]:
    with session_scope() as db:
        feedback_items = (
            db.query(EntryFeedback)
            .order_by(EntryFeedback.timestamp.desc())
            .limit(20)
            .all()
        )
        return [
            {
                "entry_id": item.entry_id,
                "digest": item.digest,
                "action": item.action_taken or "",
                "kind": item.detection_kind or "",
                "backend": item.analysis_backend or "",
                "endpoint_id": item.endpoint_id or "",
                "signature_valid": (
                    str(item.endpoint_signature_valid)
                    if item.endpoint_signature_valid is not None
                    else ""
                ),
                "timestamp": item.timestamp.isoformat(),
            }
            for item in feedback_items
        ]


def _coverage_rows() -> list[dict[str, str]]:
    with session_scope() as db:
        reports = (
            db.query(CoverageReportORM)
            .order_by(CoverageReportORM.timestamp.desc())
            .limit(20)
            .all()
        )
        return [
            {
                "entry_id": report.entry_id,
                "vendor": report.vendor,
                "detected": str(report.detected),
                "timestamp": report.timestamp.isoformat(),
            }
            for report in reports
        ]


def _review_rows() -> list[dict[str, str]]:
    with session_scope() as db:
        reviews = (
            db.query(ReviewRecordORM)
            .order_by(ReviewRecordORM.updated_at.desc())
            .limit(20)
            .all()
        )
        return [
            {
                "review_id": review.review_id,
                "entry_id": review.entry_id,
                "status": review.status,
                "requested_by": review.requested_by,
                "assigned_to": review.assigned_to or "",
                "resolution_action": review.resolution_action or "",
                "updated_at": review.updated_at.isoformat(),
            }
            for review in reviews
        ]


def _review_context(review_id: str) -> dict[str, Any]:
    with session_scope() as db:
        review = (
            db.query(ReviewRecordORM)
            .filter(ReviewRecordORM.review_id == review_id)
            .first()
        )
        if review is None:
            return {}
    return {
        "review": {
            "review_id": review.review_id,
            "entry_id": review.entry_id,
            "status": review.status,
            "reason": review.reason,
            "requested_by": review.requested_by,
            "assigned_to": review.assigned_to or "",
            "resolution_action": review.resolution_action or "",
            "resolution_notes": review.resolution_notes or "",
            "updated_at": review.updated_at.isoformat(),
        },
        "entry_detail": _entry_detail(review.entry_id),
        "notes": _review_notes(review.review_id),
    }


def _review_notes(review_id: str) -> list[dict[str, str]]:
    with session_scope() as db:
        from avchain.models.orm import ReviewNoteORM

        notes = (
            db.query(ReviewNoteORM)
            .filter(ReviewNoteORM.review_id == review_id)
            .order_by(ReviewNoteORM.created_at.asc(), ReviewNoteORM.note_id.asc())
            .all()
        )
        return [
            {
                "note_id": str(note.note_id),
                "author": note.author,
                "note": note.note,
                "created_at": note.created_at.isoformat(),
            }
            for note in notes
        ]


def _runtime_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for payload in list_status_payloads(freshness_seconds=60.0):
        rows.append(
            {
                "name": str(payload.get("name", "")),
                "worker": str(payload.get("worker", payload.get("name", ""))),
                "fresh": str(payload.get("fresh", False)),
                "heartbeat_age_seconds": str(payload.get("heartbeat_age_seconds", "")),
                "analysis_backend": str(payload.get("analysis_backend", "")),
                "llm_model": str(payload.get("llm_model", "")),
                "last_error": str(payload.get("last_error", "")),
            }
        )
    return rows


def _runtime_detail(name: str) -> dict[str, Any]:
    for payload in list_status_payloads(freshness_seconds=60.0):
        if payload.get("name") == name:
            return payload
    return {}


def _entry_detail(entry_id: str) -> dict[str, Any]:
    with session_scope() as db:
        entry = db.query(Entry).filter(Entry.id == entry_id).first()
        if entry is None:
            return {}

        events = (
            db.query(EntryEvent)
            .filter(EntryEvent.entry_id == entry_id)
            .order_by(EntryEvent.timestamp.asc())
            .all()
        )
        proposals = (
            db.query(Proposal)
            .filter(Proposal.entry_id == entry_id)
            .order_by(Proposal.timestamp.asc())
            .all()
        )
        decisions = (
            db.query(Decision)
            .filter(Decision.entry_id == entry_id)
            .order_by(Decision.timestamp.asc())
            .all()
        )
        feedback_items = (
            db.query(EntryFeedback)
            .filter(EntryFeedback.entry_id == entry_id)
            .order_by(EntryFeedback.timestamp.asc())
            .all()
        )
        review_records = (
            db.query(ReviewRecordORM)
            .filter(ReviewRecordORM.entry_id == entry_id)
            .order_by(ReviewRecordORM.updated_at.asc())
            .all()
        )
        coverage_reports = (
            db.query(CoverageReportORM)
            .filter(CoverageReportORM.entry_id == entry_id)
            .order_by(CoverageReportORM.timestamp.asc())
            .all()
        )
        evidence_links = (
            db.query(EntryEvidenceLink, EvidenceObject)
            .join(EvidenceObject, EntryEvidenceLink.digest == EvidenceObject.digest)
            .filter(EntryEvidenceLink.entry_id == entry_id)
            .order_by(EvidenceObject.created_at.asc())
            .all()
        )

        evidence_pairs = [(link, evidence) for link, evidence in evidence_links]

        return {
            "summary": {
                "id": entry.id,
                "state": entry.state,
                "observables": ", ".join(json.loads(entry.observables_json)),
                "tlp": entry.tlp_label,
                "created_at": entry.created_at.isoformat(),
                "updated_at": entry.updated_at.isoformat(),
            },
            "history": [
                {
                    "timestamp": event.timestamp.isoformat(),
                    "from_state": event.from_state or "",
                    "to_state": event.to_state,
                    "actor": event.actor,
                    "notes": event.notes or "",
                }
                for event in events
            ],
            "evidence": [
                {
                    "digest": evidence.digest,
                    "content_type": evidence.content_type,
                    "size": str(evidence.size),
                    "created_at": evidence.created_at.isoformat(),
                    "preview": _evidence_preview(
                        evidence.digest,
                        evidence.content_type,
                    ),
                }
                for _, evidence in evidence_links
            ],
            "proposals": [
                {
                    "proposal_id": proposal.proposal_id,
                    "validator_id": proposal.validator_id,
                    "action": proposal.action,
                    "confidence": f"{proposal.confidence:.2f}",
                    "backend": proposal.analysis_backend or "",
                    "llm_model": proposal.llm_model or "",
                    "prompt_version": proposal.prompt_version or "",
                    "explanation": proposal.explanation,
                    "timestamp": proposal.timestamp.isoformat(),
                }
                for proposal in proposals
            ],
            "decisions": [
                {
                    "decision_id": decision.decision_id,
                    "action": decision.action,
                    "supporting_proposals": ", ".join(
                        proposal.proposal_id for proposal in decision.proposals
                    ),
                    "timestamp": decision.timestamp.isoformat(),
                    "notes": decision.notes or "",
                }
                for decision in decisions
            ],
            "feedback": [
                {
                    "digest": item.digest,
                    "action": item.action_taken or "",
                    "kind": item.detection_kind or "",
                    "backend": item.analysis_backend or "",
                    "endpoint_id": item.endpoint_id or "",
                    "signature_valid": (
                        str(item.endpoint_signature_valid)
                        if item.endpoint_signature_valid is not None
                        else ""
                    ),
                    "matched_observables": item.matched_observables_json or "",
                    "timestamp": item.timestamp.isoformat(),
                }
                for item in feedback_items
            ],
            "coverage": [
                {
                    "vendor": report.vendor,
                    "detected": str(report.detected),
                    "timestamp": report.timestamp.isoformat(),
                }
                for report in coverage_reports
            ],
            "reviews": [
                {
                    "review_id": review.review_id,
                    "status": review.status,
                    "requested_by": review.requested_by,
                    "assigned_to": review.assigned_to or "",
                    "resolution_action": review.resolution_action or "",
                    "resolution_notes": review.resolution_notes or "",
                    "updated_at": review.updated_at.isoformat(),
                }
                for review in review_records
            ],
            "stix_summary": _stix_summary(entry_id),
            "proof_points": _proof_points(
                evidence_pairs,
                proposals,
                decisions,
                feedback_items,
                coverage_reports,
                review_records,
            ),
        }


def _stix_summary(entry_id: str) -> dict[str, str | int]:
    with session_scope() as db:
        entry = db.query(Entry).filter(Entry.id == entry_id).first()
        if entry is None:
            return {}
    detail = _entry_detail_minimal(entry_id)
    if not detail:
        return {}
    bundle = build_stix_bundle(detail)
    return {
        "bundle_id": str(bundle["id"]),
        "object_count": len(bundle["objects"]),
        "attack_pattern_count": sum(
            1 for obj in bundle["objects"] if obj.get("type") == "attack-pattern"
        ),
        "relationship_count": sum(
            1 for obj in bundle["objects"] if obj.get("type") == "relationship"
        ),
        "tlp_label": detail.tlp_label,
    }


def _entry_detail_minimal(entry_id: str) -> ThreatEntry | None:
    from avchain.ledger.crud import get_entry_or_none

    with session_scope() as db:
        return get_entry_or_none(db=db, entry_id=entry_id)


def _proof_points(
    evidence_links: list[tuple[EntryEvidenceLink, EvidenceObject]],
    proposals: list[Proposal],
    decisions: list[Decision],
    feedback_items: list[EntryFeedback],
    coverage_reports: list[CoverageReportORM],
    review_records: list[ReviewRecordORM],
) -> dict[str, bool]:
    evidence_integrity = []
    for _, evidence in evidence_links:
        payload = EvidenceStorage().retrieve_bytes(evidence.digest)
        evidence_integrity.append(
            payload is not None and compute_sha256(payload) == evidence.digest
        )
    return {
        "has_evidence": len(evidence_links) > 0,
        "all_evidence_integrity_verified": all(evidence_integrity)
        if evidence_integrity
        else False,
        "has_signed_validator_proposals": len(proposals) > 0,
        "has_consensus_decision": len(decisions) > 0,
        "has_endpoint_feedback": len(feedback_items) > 0,
        "has_coverage_reports": len(coverage_reports) > 0,
        "has_review_records": len(review_records) > 0,
        "stix_export_available": True,
    }


def _evidence_preview(digest: str, content_type: str) -> str:
    payload = EvidenceStorage().retrieve_bytes(digest)
    if payload is None:
        return ""
    if content_type == "application/json":
        try:
            rendered_json: str = json.dumps(
                json.loads(payload.decode("utf-8")),
                indent=2,
            )
            return rendered_json[:1200]
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ""
    decoded_payload: str = payload.decode("utf-8", errors="ignore")
    return decoded_payload[:1200]


def main() -> None:
    init_db()
    st.set_page_config(page_title="LLM-AVChain Dashboard", layout="wide")
    st.title("LLM-AVChain Dashboard")
    st.caption("Lifecycle state, evidence flow, consensus, and feedback at a glance.")

    entry_rows = _entry_rows()
    st.subheader("Entries")
    st.dataframe(entry_rows, use_container_width=True)

    if entry_rows:
        st.subheader("Selected Entry")
        selected_entry_id = st.selectbox(
            "Entry ID",
            options=[row["id"] for row in entry_rows],
            index=0,
        )
        detail = _entry_detail(selected_entry_id)
        summary = detail.get("summary", {})
        summary_columns = st.columns(4)
        summary_columns[0].metric("State", str(summary.get("state", "")))
        evidence_rows = detail.get("evidence", [])
        feedback_rows = detail.get("feedback", [])
        coverage_rows = detail.get("coverage", [])
        summary_columns[1].metric("Evidence Items", len(evidence_rows))
        summary_columns[2].metric("Feedback Records", len(feedback_rows))
        summary_columns[3].metric("Coverage Reports", len(coverage_rows))
        st.json(summary)
        reviewer_left, reviewer_right = st.columns(2)
        with reviewer_left:
            st.caption("Reviewer Proof Points")
            st.json(detail.get("proof_points", {}))
        with reviewer_right:
            st.caption("STIX Export Summary")
            st.json(detail.get("stix_summary", {}))
        detail_left, detail_right = st.columns(2)
        with detail_left:
            st.caption("Lifecycle History")
            st.dataframe(detail.get("history", []), use_container_width=True)
            st.caption("Evidence")
            st.dataframe(evidence_rows, use_container_width=True)
            st.caption("Feedback")
            st.dataframe(feedback_rows, use_container_width=True)
        with detail_right:
            st.caption("Validator Proposals")
            st.dataframe(detail.get("proposals", []), use_container_width=True)
            st.caption("Consensus Decisions")
            st.dataframe(detail.get("decisions", []), use_container_width=True)
            st.caption("Coverage Reports")
            st.dataframe(coverage_rows, use_container_width=True)
            st.caption("Review Records")
            st.dataframe(detail.get("reviews", []), use_container_width=True)

    left, right = st.columns(2)
    with left:
        st.subheader("Events")
        st.dataframe(_event_rows(), use_container_width=True)
        st.subheader("Decisions")
        st.dataframe(_decision_rows(), use_container_width=True)
    with right:
        st.subheader("Proposals")
        st.dataframe(_proposal_rows(), use_container_width=True)
        st.subheader("Feedback")
        st.dataframe(_feedback_rows(), use_container_width=True)

    st.subheader("Coverage Reports")
    st.dataframe(_coverage_rows(), use_container_width=True)
    st.subheader("Review Queue")
    review_rows = _review_rows()
    st.dataframe(review_rows, use_container_width=True)
    if review_rows:
        selected_review_id = st.selectbox(
            "Review Record",
            options=[row["review_id"] for row in review_rows],
            index=0,
        )
        review_context = _review_context(selected_review_id)
        st.caption("Selected Review Context")
        st.json(review_context.get("review", {}))
        entry_detail = review_context.get("entry_detail", {})
        review_left, review_right = st.columns(2)
        with review_left:
            st.caption("Review Notes")
            st.dataframe(review_context.get("notes", []), use_container_width=True)
            st.caption("Review Entry Evidence")
            st.dataframe(entry_detail.get("evidence", []), use_container_width=True)
            st.caption("Review Entry Feedback")
            st.dataframe(entry_detail.get("feedback", []), use_container_width=True)
        with review_right:
            st.caption("Review Entry Proposals")
            st.dataframe(entry_detail.get("proposals", []), use_container_width=True)
            st.caption("Review Entry Decisions")
            st.dataframe(entry_detail.get("decisions", []), use_container_width=True)
    runtime_rows = _runtime_rows()
    st.subheader("Runtime Status")
    st.dataframe(runtime_rows, use_container_width=True)
    if runtime_rows:
        selected_runtime_name = st.selectbox(
            "Runtime Worker",
            options=[row["name"] for row in runtime_rows],
            index=0,
        )
        st.json(_runtime_detail(selected_runtime_name))


if __name__ == "__main__":
    main()
