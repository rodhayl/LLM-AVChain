from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from avchain.ledger.crud import append_transition, get_entry
from avchain.models.enums import LifecycleState
from avchain.models.orm import ReviewNoteORM, ReviewRecordORM
from avchain.models.schemas import (
    ReviewAction,
    ReviewAssignment,
    ReviewNote,
    ReviewNoteCreate,
    ReviewRecord,
    ReviewRecordCreate,
)
from avchain.utils.helpers import current_timestamp


def list_review_records(
    db: Session,
    *,
    status: str | None = None,
    entry_id: str | None = None,
) -> list[ReviewRecord]:
    query = db.query(ReviewRecordORM)
    if status is not None:
        query = query.filter(ReviewRecordORM.status == status)
    if entry_id is not None:
        query = query.filter(ReviewRecordORM.entry_id == entry_id)
    rows = query.order_by(ReviewRecordORM.updated_at.desc()).all()
    return [_to_schema(row) for row in rows]


def get_review_record(db: Session, review_id: str | UUID) -> ReviewRecord:
    row = db.get(ReviewRecordORM, str(review_id))
    if row is None:
        raise LookupError("Review record not found")
    return _to_schema(row)


def create_review_record(db: Session, payload: ReviewRecordCreate) -> ReviewRecord:
    _ = get_entry(db, payload.entry_id)
    row = ReviewRecordORM(
        entry_id=str(payload.entry_id),
        reason=payload.reason,
        status="open",
        requested_by=payload.requested_by,
        assigned_to=payload.assigned_to,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    add_review_note(
        db,
        review_id=row.review_id,
        payload=ReviewNoteCreate(
            author=payload.requested_by,
            note=f"Review opened: {payload.reason}",
        ),
    )
    return _to_schema(row)


def open_review_record_for_entry(
    db: Session,
    *,
    entry_id: str | UUID,
    reason: str,
    requested_by: str,
) -> ReviewRecord:
    existing = (
        db.query(ReviewRecordORM)
        .filter(ReviewRecordORM.entry_id == str(entry_id))
        .filter(ReviewRecordORM.status == "open")
        .order_by(ReviewRecordORM.updated_at.desc())
        .first()
    )
    if existing is not None:
        existing.updated_at = current_timestamp()
        if reason and existing.reason != reason:
            existing.reason = reason
        db.commit()
        db.refresh(existing)
        return _to_schema(existing)
    return create_review_record(
        db,
        ReviewRecordCreate(
            entry_id=UUID(str(entry_id)),
            reason=reason,
            requested_by=requested_by,
        ),
    )


def apply_review_action(
    db: Session,
    *,
    review_id: str | UUID,
    payload: ReviewAction,
) -> ReviewRecord:
    row = db.get(ReviewRecordORM, str(review_id))
    if row is None:
        raise LookupError("Review record not found")
    entry = get_entry(db, row.entry_id)

    if payload.action == "approve_confirmed":
        if entry.state != LifecycleState.REVIEW:
            raise ValueError("Only review entries can be approved back to confirmed")
        append_transition(
            db=db,
            entry_id=row.entry_id,
            from_state=LifecycleState.REVIEW,
            to_state=LifecycleState.CONFIRMED,
            actor=payload.actor,
            notes=payload.notes or row.reason,
        )
        row.status = "approved"
    elif payload.action == "deprecate":
        if entry.state != LifecycleState.REVIEW:
            raise ValueError("Only review entries can be deprecated")
        append_transition(
            db=db,
            entry_id=row.entry_id,
            from_state=LifecycleState.REVIEW,
            to_state=LifecycleState.DEPRECATED,
            actor=payload.actor,
            notes=payload.notes or row.reason,
        )
        row.status = "deprecated"
    elif payload.action == "reopen_review":
        if entry.state != LifecycleState.CONFIRMED:
            raise ValueError("Only confirmed entries can be reopened for review")
        append_transition(
            db=db,
            entry_id=row.entry_id,
            from_state=LifecycleState.CONFIRMED,
            to_state=LifecycleState.REVIEW,
            actor=payload.actor,
            notes=payload.notes or row.reason,
        )
        row.status = "reopened"
    elif payload.action == "close_noop":
        row.status = "closed"
    else:
        raise ValueError("Unsupported review action")

    row.resolution_action = payload.action
    row.resolution_notes = payload.notes
    row.updated_at = current_timestamp()
    db.commit()
    db.refresh(row)
    add_review_note(
        db,
        review_id=row.review_id,
        payload=ReviewNoteCreate(
            author=payload.actor,
            note=(
                f"Review action applied: {payload.action}"
                + (f" ({payload.notes})" if payload.notes else "")
            ),
        ),
    )
    return _to_schema(row)


def assign_review_record(
    db: Session,
    *,
    review_id: str | UUID,
    payload: ReviewAssignment,
) -> ReviewRecord:
    row = db.get(ReviewRecordORM, str(review_id))
    if row is None:
        raise LookupError("Review record not found")
    row.assigned_to = payload.assigned_to
    row.updated_at = current_timestamp()
    db.commit()
    db.refresh(row)
    add_review_note(
        db,
        review_id=row.review_id,
        payload=ReviewNoteCreate(
            author=payload.actor,
            note=f"Assigned review to {payload.assigned_to}",
        ),
    )
    return _to_schema(row)


def list_review_notes(
    db: Session,
    *,
    review_id: str | UUID,
) -> list[ReviewNote]:
    review = db.get(ReviewRecordORM, str(review_id))
    if review is None:
        raise LookupError("Review record not found")
    rows = (
        db.query(ReviewNoteORM)
        .filter(ReviewNoteORM.review_id == str(review_id))
        .order_by(ReviewNoteORM.created_at.asc(), ReviewNoteORM.note_id.asc())
        .all()
    )
    return [_note_to_schema(row) for row in rows]


def add_review_note(
    db: Session,
    *,
    review_id: str | UUID,
    payload: ReviewNoteCreate,
) -> ReviewNote:
    review = db.get(ReviewRecordORM, str(review_id))
    if review is None:
        raise LookupError("Review record not found")
    row = ReviewNoteORM(
        review_id=str(review_id),
        author=payload.author,
        note=payload.note,
    )
    review.updated_at = current_timestamp()
    db.add(row)
    db.commit()
    db.refresh(row)
    return _note_to_schema(row)


def _to_schema(row: ReviewRecordORM) -> ReviewRecord:
    return ReviewRecord(
        review_id=UUID(row.review_id),
        entry_id=UUID(row.entry_id),
        reason=row.reason,
        status=row.status,
        requested_by=row.requested_by,
        assigned_to=row.assigned_to,
        resolution_action=row.resolution_action,
        resolution_notes=row.resolution_notes,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _note_to_schema(row: ReviewNoteORM) -> ReviewNote:
    return ReviewNote(
        note_id=row.note_id,
        review_id=UUID(row.review_id),
        author=row.author,
        note=row.note,
        created_at=row.created_at,
    )
