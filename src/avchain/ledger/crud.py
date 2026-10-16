from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session, selectinload

from avchain.crypto.keys import canonicalize, load_public_key, verify_signature
from avchain.endpoint.registry import get_endpoint_registry
from avchain.evidence.storage import (
    EvidenceStorage,
    encode_evidence_payload,
    store_evidence_item,
)
from avchain.models.enums import LifecycleState
from avchain.models.orm import (
    Entry,
    EntryEvent,
    EntryEvidenceLink,
    EntryFeedback,
    EvidenceObject,
    Proposal,
)
from avchain.models.schemas import (
    FeedbackRecord,
    LifecycleEvent,
    ThreatEntry,
    ThreatEntryCreate,
)
from avchain.utils.helpers import current_timestamp

# Source docs disagree on whether stale suspected entries should timeout
# directly to deprecated or move through review first. The shipped POC keeps
# direct suspected->deprecated available for explicit transitions, while timeout
# automation follows the documented workflow of suspected->review.
VALID_TRANSITIONS: dict[LifecycleState, set[LifecycleState]] = {
    LifecycleState.SUSPECTED: {
        LifecycleState.CONFIRMED,
        LifecycleState.REVIEW,
        LifecycleState.DEPRECATED,
    },
    LifecycleState.CONFIRMED: {LifecycleState.REVIEW},
    LifecycleState.REVIEW: {
        LifecycleState.CONFIRMED,
        LifecycleState.DEPRECATED,
    },
    LifecycleState.DEPRECATED: set(),
}


def create_entry(
    db: Session,
    data: ThreatEntryCreate,
    storage: EvidenceStorage,
) -> ThreatEntry:
    now = current_timestamp()
    entry = Entry(
        observables_json=json.dumps(data.observables),
        state=LifecycleState.SUSPECTED.value,
        attack_techniques_json=(
            json.dumps(data.attack_techniques) if data.attack_techniques else None
        ),
        tlp_label=data.tlp_label,
        created_at=now,
        updated_at=now,
    )
    db.add(entry)
    db.flush()

    db.add(
        EntryEvent(
            entry_id=entry.id,
            from_state=None,
            to_state=LifecycleState.SUSPECTED.value,
            actor="creator",
            proposal_ids_json="[]",
            notes="Entry created",
            timestamp=now,
        )
    )

    for evidence in data.evidence:
        payload = encode_evidence_payload(evidence.data, evidence.content_type)
        store_evidence_item(
            db=db,
            storage=storage,
            entry_id=entry.id,
            data=payload,
            content_type=evidence.content_type,
        )

    db.commit()
    return get_entry(db, entry.id)


def get_entry(db: Session, entry_id: str | UUID) -> ThreatEntry:
    entry = _get_entry_orm(db, str(entry_id))
    if entry is None:
        raise LookupError("Entry not found")
    return _entry_to_schema(entry)


def get_entry_or_none(db: Session, entry_id: str | UUID) -> ThreatEntry | None:
    entry = _get_entry_orm(db, str(entry_id))
    return None if entry is None else _entry_to_schema(entry)


def list_entries(
    db: Session,
    state: LifecycleState | None = None,
) -> list[ThreatEntry]:
    query = db.query(Entry).options(
        selectinload(Entry.events),
        selectinload(Entry.evidence_links).selectinload(
            EntryEvidenceLink.evidence_item
        ),
    )
    if state is not None:
        query = query.filter(Entry.state == state.value)
    entries = query.order_by(Entry.created_at.asc()).all()
    return [_entry_to_schema(entry) for entry in entries]


def append_transition(
    db: Session,
    entry_id: str | UUID,
    from_state: LifecycleState,
    to_state: LifecycleState,
    actor: str,
    proposal_ids: list[str] | None = None,
    notes: str | None = None,
) -> ThreatEntry:
    if to_state not in VALID_TRANSITIONS.get(from_state, set()):
        raise ValueError("Invalid transition")

    entry = _get_entry_orm(db, str(entry_id))
    if entry is None:
        raise LookupError("Entry not found")
    if LifecycleState(entry.state) != from_state:
        raise ValueError("Entry state mismatch")

    now = current_timestamp()
    db.add(
        EntryEvent(
            entry_id=entry.id,
            from_state=from_state.value,
            to_state=to_state.value,
            actor=actor,
            proposal_ids_json=json.dumps(proposal_ids or []),
            notes=notes,
            timestamp=now,
        )
    )
    entry.state = to_state.value
    entry.updated_at = now
    db.commit()
    return get_entry(db, entry.id)


def record_feedback(db: Session, entry_id: str | UUID, digest: str) -> datetime:
    entry = _get_entry_orm(db, str(entry_id))
    if entry is None:
        raise LookupError("Entry not found")
    if LifecycleState(entry.state) not in {
        LifecycleState.CONFIRMED,
        LifecycleState.REVIEW,
    }:
        raise ValueError("Feedback is only valid for confirmed or review entries")
    evidence_item = db.get(EvidenceObject, digest)
    if evidence_item is None:
        raise ValueError("Feedback digest is unknown")
    if evidence_item.purpose != "feedback" or evidence_item.entry_id != entry.id:
        raise ValueError("Feedback digest must be uploaded as feedback for this entry")

    timestamp = current_timestamp()
    feedback_payload = _load_feedback_payload(digest)
    feedback_metadata = _load_feedback_metadata(digest)
    endpoint_signature = _verify_endpoint_signature(feedback_metadata)
    if (
        feedback_metadata is not None
        and "signature" in feedback_metadata
        and endpoint_signature is False
    ):
        raise ValueError("Endpoint signature is invalid")
    endpoint_id = None
    if feedback_metadata is not None:
        raw_endpoint_id = feedback_metadata.get("endpoint_id")
        if isinstance(raw_endpoint_id, str) and raw_endpoint_id:
            endpoint_id = raw_endpoint_id
    db.add(
        EntryFeedback(
            entry_id=entry.id,
            digest=digest,
            timestamp=timestamp,
            action_taken=(
                feedback_payload.action_taken if feedback_payload is not None else None
            ),
            detection_kind=(
                feedback_payload.detection_kind
                if feedback_payload is not None
                else None
            ),
            matched_observables_json=(
                json.dumps(feedback_payload.matched_observables)
                if feedback_payload is not None and feedback_payload.matched_observables
                else None
            ),
            analysis_backend=(
                feedback_payload.provenance.analysis_backend
                if feedback_payload is not None
                and feedback_payload.provenance is not None
                else None
            ),
            llm_provider=(
                feedback_payload.provenance.llm_provider
                if feedback_payload is not None
                and feedback_payload.provenance is not None
                else None
            ),
            llm_model=(
                feedback_payload.provenance.llm_model
                if feedback_payload is not None
                and feedback_payload.provenance is not None
                else None
            ),
            prompt_name=(
                feedback_payload.provenance.prompt_name
                if feedback_payload is not None
                and feedback_payload.provenance is not None
                else None
            ),
            prompt_version=(
                feedback_payload.provenance.prompt_version
                if feedback_payload is not None
                and feedback_payload.provenance is not None
                else None
            ),
            endpoint_id=endpoint_id,
            endpoint_signature_valid=endpoint_signature,
        )
    )
    db.commit()
    return timestamp


def run_timeout_transitions(
    db: Session,
    suspected_timeout_hours: float,
    review_timeout_hours: float,
    now: datetime | None = None,
) -> list[str]:
    reference_time = now or current_timestamp()
    changed_entries: list[str] = []

    suspected_deadline = reference_time - timedelta(hours=suspected_timeout_hours)
    review_deadline = reference_time - timedelta(hours=review_timeout_hours)

    suspected_entries = (
        db.query(Entry).filter(Entry.state == LifecycleState.SUSPECTED.value).all()
    )
    for entry in suspected_entries:
        if _coerce_utc(entry.updated_at) > suspected_deadline:
            continue
        if not _has_recent_proposal_activity(
            db=db,
            entry_id=entry.id,
            entry_updated_at=entry.updated_at,
            activity_deadline=suspected_deadline,
        ):
            append_transition(
                db=db,
                entry_id=entry.id,
                from_state=LifecycleState.SUSPECTED,
                to_state=LifecycleState.REVIEW,
                actor="timeout",
                notes="Suspected entry expired without proposals",
            )
            changed_entries.append(entry.id)

    review_entries = (
        db.query(Entry).filter(Entry.state == LifecycleState.REVIEW.value).all()
    )
    for entry in review_entries:
        if _coerce_utc(entry.updated_at) > review_deadline:
            continue
        if not _has_recent_proposal_activity(
            db=db,
            entry_id=entry.id,
            entry_updated_at=entry.updated_at,
            activity_deadline=review_deadline,
        ):
            append_transition(
                db=db,
                entry_id=entry.id,
                from_state=LifecycleState.REVIEW,
                to_state=LifecycleState.DEPRECATED,
                actor="timeout",
                notes="Review entry expired without proposals",
            )
            changed_entries.append(entry.id)

    return changed_entries


def _get_entry_orm(db: Session, entry_id: str) -> Entry | None:
    return (
        db.query(Entry)
        .options(
            selectinload(Entry.events),
            selectinload(Entry.evidence_links).selectinload(
                EntryEvidenceLink.evidence_item
            ),
        )
        .filter(Entry.id == entry_id)
        .first()
    )


def _entry_to_schema(entry: Entry) -> ThreatEntry:
    evidence_digests = [
        link.digest
        for link in sorted(entry.evidence_links, key=lambda item: item.digest)
    ]
    history = [
        LifecycleEvent(
            timestamp=event.timestamp,
            from_state=(
                LifecycleState(event.from_state)
                if event.from_state is not None
                else None
            ),
            to_state=LifecycleState(event.to_state),
            actor=event.actor,
            proposal_ids=json.loads(event.proposal_ids_json),
            notes=event.notes,
        )
        for event in sorted(entry.events, key=lambda item: item.timestamp)
    ]
    attack_techniques = (
        json.loads(entry.attack_techniques_json)
        if entry.attack_techniques_json is not None
        else None
    )
    return ThreatEntry(
        id=UUID(entry.id),
        observables=json.loads(entry.observables_json),
        evidence_digests=evidence_digests,
        state=LifecycleState(entry.state),
        attack_techniques=attack_techniques,
        tlp_label=entry.tlp_label,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
        history=history,
    )


def _coerce_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _has_recent_proposal_activity(
    db: Session,
    entry_id: str,
    entry_updated_at: datetime,
    activity_deadline: datetime,
) -> bool:
    activity_since = max(_coerce_utc(entry_updated_at), _coerce_utc(activity_deadline))
    return (
        db.query(Proposal)
        .filter(Proposal.entry_id == entry_id)
        .filter(Proposal.timestamp >= activity_since)
        .count()
        > 0
    )


def _load_feedback_payload(digest: str) -> FeedbackRecord | None:
    decoded = _load_feedback_metadata(digest)
    if decoded is None:
        return None
    try:
        return FeedbackRecord.model_validate(decoded)
    except Exception:
        return None


def _load_feedback_metadata(digest: str) -> dict[str, object] | None:
    payload = EvidenceStorage().retrieve_bytes(digest)
    if payload is None:
        return None
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(decoded, dict):
        return decoded
    return None


def _verify_endpoint_signature(payload: dict[str, object] | None) -> bool | None:
    if payload is None:
        return None
    endpoint_id = payload.get("endpoint_id")
    signature = payload.get("signature")
    if not isinstance(endpoint_id, str) or not isinstance(signature, str):
        return None
    record = get_endpoint_registry().get(endpoint_id)
    if record is None:
        return False
    if not record.enabled:
        return False
    unsigned_payload = {
        key: value for key, value in payload.items() if key != "signature"
    }
    try:
        public_key = load_public_key(record.public_key)
    except (TypeError, ValueError):
        return False
    return verify_signature(public_key, canonicalize(unsigned_payload), signature)
