from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Annotated
from uuid import UUID, uuid5

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session

from avchain.auth.dependencies import require_ledger_key
from avchain.config.settings import get_settings
from avchain.coverage.central import central_router
from avchain.database.core import get_session, init_db, session_scope
from avchain.endpoint.registry import get_endpoint_registry
from avchain.evidence.storage import EvidenceStorage, list_evidence_items
from avchain.incident.api import knowledge_router
from avchain.ledger.crud import (
    append_transition,
    create_entry,
    get_entry_or_none,
    list_entries,
    record_feedback,
    run_timeout_transitions,
)
from avchain.models.enums import LifecycleState, ProposalAction
from avchain.models.orm import (
    CoverageReportORM,
    Entry,
    EntryFeedback,
    ReviewRecordORM,
)
from avchain.models.orm import (
    Decision as DecisionORM,
)
from avchain.models.orm import (
    Proposal as ProposalORM,
)
from avchain.models.schemas import (
    AnalysisProvenance,
    CoverageReport,
    Decision,
    EvidenceIntegrityRecord,
    FeedbackRecord,
    FeedbackSubmission,
    Proposal,
    ReviewAction,
    ReviewAssignment,
    ReviewerPacket,
    ReviewNote,
    ReviewNoteCreate,
    ReviewRecord,
    ReviewRecordCreate,
    StateTransition,
    StixExportSummary,
    ThreatEntry,
    ThreatEntryCreate,
)
from avchain.review import (
    add_review_note,
    apply_review_action,
    assign_review_record,
    create_review_record,
    get_review_record,
    list_review_notes,
    list_review_records,
    open_review_record_for_entry,
)
from avchain.stix_taxii import (
    TaxiiClient,
    build_stix_bundle,
    import_stix_bundle,
    preview_stix_bundle,
    validate_stix_bundle,
)
from avchain.utils.api import attach_api_contract_handlers
from avchain.utils.helpers import compute_sha256
from avchain.utils.runtime_status import (
    heartbeat_age_seconds,
    is_status_fresh,
    list_status_payloads,
    read_status,
)

LedgerAPIKey = Annotated[str, Depends(require_ledger_key)]
DBSession = Annotated[Session, Depends(get_session)]


async def _timeout_worker() -> None:
    settings = get_settings()
    while True:
        await asyncio.sleep(max(settings.poll_interval, 1))
        with session_scope() as db:
            run_timeout_transitions(
                db=db,
                suspected_timeout_hours=settings.suspected_timeout_hours,
                review_timeout_hours=settings.review_timeout_hours,
            )


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    timeout_task = asyncio.create_task(_timeout_worker())
    try:
        yield
    finally:
        timeout_task.cancel()
        with suppress(asyncio.CancelledError):
            await timeout_task


def create_app(storage: EvidenceStorage | None = None) -> FastAPI:
    settings = get_settings()
    evidence_storage = storage or EvidenceStorage()
    app = FastAPI(title="LLM-AVChain Ledger", version="0.1.0", lifespan=_lifespan)
    attach_api_contract_handlers(app)
    app.include_router(knowledge_router(evidence_storage))
    app.include_router(central_router(evidence_storage))

    @app.post(
        "/ledger/entries",
        response_model=ThreatEntry,
        status_code=status.HTTP_201_CREATED,
    )
    def post_create_entry(
        payload: ThreatEntryCreate,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> ThreatEntry:
        return create_entry(db=db, data=payload, storage=evidence_storage)

    @app.get("/ledger/entries", response_model=list[ThreatEntry])
    def get_entries(
        _: LedgerAPIKey,
        db: DBSession,
        state: LifecycleState | None = None,
    ) -> list[ThreatEntry]:
        return list_entries(db=db, state=state)

    @app.get("/health")
    def health(_: LedgerAPIKey, db: DBSession) -> dict[str, object]:
        return {
            "service": "ledger",
            "status": "ok",
            "entries": db.query(Entry).count(),
            "open_reviews": db.query(ReviewRecordORM)
            .filter(ReviewRecordORM.status == "open")
            .count(),
        }

    @app.get("/runtime/status")
    def get_runtime_statuses(_: LedgerAPIKey) -> list[dict[str, object]]:
        return list_status_payloads(freshness_seconds=60.0)

    @app.get("/runtime/status/{name}")
    def get_runtime_status(name: str, _: LedgerAPIKey) -> dict[str, object]:
        payload = read_status(name)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Runtime status not found",
            )
        return {
            "name": name,
            "fresh": is_status_fresh(payload, freshness_seconds=60.0),
            "heartbeat_age_seconds": heartbeat_age_seconds(payload),
            **payload,
        }

    @app.get("/ledger/entries/{entry_id}", response_model=ThreatEntry)
    def get_entry_by_id(entry_id: str, _: LedgerAPIKey, db: DBSession) -> ThreatEntry:
        entry = get_entry_or_none(db=db, entry_id=entry_id)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        return entry

    @app.get(
        "/ledger/entries/{entry_id}/reviewer_packet",
        response_model=ReviewerPacket,
    )
    def get_entry_reviewer_packet(
        entry_id: str,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> ReviewerPacket:
        entry = get_entry_or_none(db=db, entry_id=entry_id)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )

        proposals = (
            db.query(ProposalORM)
            .filter(ProposalORM.entry_id == entry_id)
            .order_by(ProposalORM.timestamp.asc())
            .all()
        )
        decisions = (
            db.query(DecisionORM)
            .filter(DecisionORM.entry_id == entry_id)
            .order_by(DecisionORM.timestamp.asc())
            .all()
        )
        feedback_rows = (
            db.query(EntryFeedback)
            .filter(EntryFeedback.entry_id == entry_id)
            .order_by(EntryFeedback.timestamp.asc())
            .all()
        )
        coverage_rows = (
            db.query(CoverageReportORM)
            .filter(CoverageReportORM.entry_id == entry_id)
            .order_by(CoverageReportORM.timestamp.asc())
            .all()
        )
        review_rows = (
            db.query(ReviewRecordORM)
            .filter(ReviewRecordORM.entry_id == entry_id)
            .order_by(ReviewRecordORM.updated_at.asc())
            .all()
        )
        review_notes = []
        for review in review_rows:
            review_notes.extend(list_review_notes(db=db, review_id=review.review_id))

        evidence_integrity = _build_evidence_integrity_records(
            db=db,
            storage=evidence_storage,
            entry_id=entry_id,
        )
        stix_bundle = build_stix_bundle(entry)
        validate_stix_bundle(stix_bundle)

        return ReviewerPacket(
            entry=entry,
            evidence_integrity=evidence_integrity,
            proposals=[_proposal_to_schema(row) for row in proposals],
            decisions=[_decision_to_schema(row) for row in decisions],
            feedback=[
                _feedback_row_to_schema(row, evidence_storage) for row in feedback_rows
            ],
            coverage_reports=[
                CoverageReport(
                    report_id=UUID(report.report_id),
                    entry_id=UUID(report.entry_id),
                    vendor=report.vendor,
                    detected=report.detected,
                    timestamp=report.timestamp,
                )
                for report in coverage_rows
            ],
            reviews=[
                ReviewRecord(
                    review_id=UUID(review.review_id),
                    entry_id=UUID(review.entry_id),
                    reason=review.reason,
                    status=review.status,
                    requested_by=review.requested_by,
                    assigned_to=review.assigned_to,
                    resolution_action=review.resolution_action,
                    resolution_notes=review.resolution_notes,
                    created_at=review.created_at,
                    updated_at=review.updated_at,
                )
                for review in review_rows
            ],
            review_notes=review_notes,
            stix_summary=StixExportSummary(
                bundle_id=str(stix_bundle["id"]),
                object_count=len(stix_bundle["objects"]),
                attack_pattern_count=sum(
                    1
                    for obj in stix_bundle["objects"]
                    if obj.get("type") == "attack-pattern"
                ),
                relationship_count=sum(
                    1
                    for obj in stix_bundle["objects"]
                    if obj.get("type") == "relationship"
                ),
                tlp_label=entry.tlp_label,
            ),
            proof_points={
                "has_evidence": len(entry.evidence_digests) > 0,
                "all_evidence_integrity_verified": all(
                    item.file_present and item.digest_matches
                    for item in evidence_integrity
                )
                if evidence_integrity
                else False,
                "has_signed_validator_proposals": len(proposals) > 0,
                "has_consensus_decision": len(decisions) > 0,
                "has_endpoint_feedback": len(feedback_rows) > 0,
                "has_coverage_reports": len(coverage_rows) > 0,
                "has_review_records": len(review_rows) > 0,
                "stix_export_available": True,
            },
        )

    @app.post("/ledger/entries/{entry_id}/transitions", response_model=ThreatEntry)
    def post_transition(
        entry_id: str,
        payload: StateTransition,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> ThreatEntry:
        try:
            entry = append_transition(
                db=db,
                entry_id=entry_id,
                from_state=payload.from_state,
                to_state=payload.to_state,
                actor=payload.actor,
                proposal_ids=payload.proposal_ids,
                notes=payload.notes,
            )
        except LookupError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        if payload.to_state == LifecycleState.REVIEW:
            open_review_record_for_entry(
                db=db,
                entry_id=entry_id,
                reason=payload.notes or "Entry moved to review",
                requested_by=payload.actor,
            )
        return entry

    @app.post(
        "/ledger/entries/{entry_id}/feedback", status_code=status.HTTP_201_CREATED
    )
    def post_feedback(
        entry_id: str,
        payload: FeedbackSubmission,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> dict[str, str]:
        try:
            timestamp = record_feedback(db=db, entry_id=entry_id, digest=payload.digest)
        except LookupError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        return {"status": "accepted", "timestamp": timestamp.isoformat()}

    @app.get("/ledger/entries/{entry_id}/stix")
    def get_entry_stix(
        entry_id: str,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> dict[str, object]:
        try:
            entry = get_entry_or_none(db=db, entry_id=entry_id)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        bundle = build_stix_bundle(entry)
        validate_stix_bundle(bundle)
        return bundle

    @app.post("/ledger/entries/{entry_id}/taxii/publish")
    async def publish_entry_taxii(
        entry_id: str,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> dict[str, object]:
        entry = get_entry_or_none(db=db, entry_id=entry_id)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        if not settings.taxii_base_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="TAXII base URL is not configured",
            )
        bundle = build_stix_bundle(entry)
        validate_stix_bundle(bundle)
        response = await TaxiiClient(
            base_url=settings.taxii_base_url,
            api_key=settings.taxii_api_key or None,
        ).publish_bundle(
            collection_id=settings.taxii_collection_id,
            bundle=bundle,
        )
        return {
            "status": "published",
            "collection_id": settings.taxii_collection_id,
            "taxii_response": response,
        }

    @app.post("/stix/import/preview", response_model=ThreatEntryCreate)
    def post_stix_import_preview(
        bundle: dict[str, object],
        _: LedgerAPIKey,
    ) -> ThreatEntryCreate:
        try:
            return preview_stix_bundle(bundle)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    @app.post("/stix/import", response_model=ThreatEntry, status_code=201)
    def post_stix_import(
        bundle: dict[str, object],
        _: LedgerAPIKey,
        db: DBSession,
    ) -> ThreatEntry:
        try:
            validate_stix_bundle(bundle)
            payload = import_stix_bundle(bundle)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        return create_entry(db=db, data=payload, storage=evidence_storage)

    @app.get(
        "/taxii/collections/{collection_id}/preview",
        response_model=ThreatEntryCreate,
    )
    async def get_taxii_collection_preview(
        collection_id: str,
        _: LedgerAPIKey,
    ) -> ThreatEntryCreate:
        if not settings.taxii_base_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="TAXII base URL is not configured",
            )
        bundle = await TaxiiClient(
            base_url=settings.taxii_base_url,
            api_key=settings.taxii_api_key or None,
        ).fetch_collection_objects(collection_id=collection_id)
        try:
            validate_stix_bundle(bundle)
            return preview_stix_bundle(bundle)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    @app.post("/taxii/collections/{collection_id}/import", response_model=ThreatEntry)
    async def post_taxii_collection_import(
        collection_id: str,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> ThreatEntry:
        if not settings.taxii_base_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="TAXII base URL is not configured",
            )
        bundle = await TaxiiClient(
            base_url=settings.taxii_base_url,
            api_key=settings.taxii_api_key or None,
        ).fetch_collection_objects(collection_id=collection_id)
        try:
            validate_stix_bundle(bundle)
            payload = import_stix_bundle(bundle)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        return create_entry(db=db, data=payload, storage=evidence_storage)

    @app.get("/review/records", response_model=list[ReviewRecord])
    def get_review_records(
        _: LedgerAPIKey,
        db: DBSession,
        status: str | None = None,
        entry_id: str | None = None,
    ) -> list[ReviewRecord]:
        return list_review_records(db=db, status=status, entry_id=entry_id)

    @app.post("/review/records", response_model=ReviewRecord, status_code=201)
    def post_review_record(
        payload: ReviewRecordCreate,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> ReviewRecord:
        try:
            return create_review_record(db=db, payload=payload)
        except LookupError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

    @app.get("/review/records/{review_id}", response_model=ReviewRecord)
    def get_review_record_by_id(
        review_id: str,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> ReviewRecord:
        try:
            return get_review_record(db=db, review_id=review_id)
        except LookupError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

    @app.get("/review/records/{review_id}/context")
    def get_review_record_context(
        review_id: str,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> dict[str, object]:
        try:
            review = get_review_record(db=db, review_id=review_id)
            entry = get_entry_or_none(db=db, entry_id=review.entry_id)
        except LookupError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        return {
            "review": review.model_dump(mode="json"),
            "entry": entry.model_dump(mode="json"),
            "notes": [
                note.model_dump(mode="json")
                for note in list_review_notes(db=db, review_id=review_id)
            ],
        }

    @app.get("/review/records/{review_id}/notes", response_model=list[ReviewNote])
    def get_review_record_notes(
        review_id: str,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> list[ReviewNote]:
        try:
            return list_review_notes(db=db, review_id=review_id)
        except LookupError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

    @app.post(
        "/review/records/{review_id}/notes",
        response_model=ReviewNote,
        status_code=201,
    )
    def post_review_record_note(
        review_id: str,
        payload: ReviewNoteCreate,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> ReviewNote:
        try:
            return add_review_note(db=db, review_id=review_id, payload=payload)
        except LookupError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

    @app.post("/review/records/{review_id}/assign", response_model=ReviewRecord)
    def post_review_assignment(
        review_id: str,
        payload: ReviewAssignment,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> ReviewRecord:
        try:
            return assign_review_record(db=db, review_id=review_id, payload=payload)
        except LookupError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

    @app.post("/review/records/{review_id}/actions", response_model=ReviewRecord)
    def post_review_action(
        review_id: str,
        payload: ReviewAction,
        _: LedgerAPIKey,
        db: DBSession,
    ) -> ReviewRecord:
        try:
            return apply_review_action(db=db, review_id=review_id, payload=payload)
        except LookupError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    @app.get("/trust/endpoints")
    def get_trusted_endpoints(_: LedgerAPIKey) -> list[dict[str, object]]:
        return [
            {
                "endpoint_id": record.endpoint_id,
                "enabled": record.enabled,
                "trust_tier": record.trust_tier,
            }
            for record in get_endpoint_registry().list_records()
        ]

    @app.get("/trust/endpoints/{endpoint_id}")
    def get_trusted_endpoint(
        endpoint_id: str,
        _: LedgerAPIKey,
    ) -> dict[str, object]:
        record = get_endpoint_registry().get(endpoint_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Endpoint registry record not found",
            )
        return {
            "endpoint_id": record.endpoint_id,
            "enabled": record.enabled,
            "trust_tier": record.trust_tier,
        }

    return app


app = create_app()


def _build_evidence_integrity_records(
    *,
    db: Session,
    storage: EvidenceStorage,
    entry_id: str,
) -> list[EvidenceIntegrityRecord]:
    integrity_rows: list[EvidenceIntegrityRecord] = []
    for item in list_evidence_items(db, entry_id):
        payload = storage.retrieve_bytes(item.digest)
        file_present = payload is not None
        digest_matches = False
        if payload is not None:
            digest_matches = compute_sha256(payload) == item.digest
        integrity_rows.append(
            EvidenceIntegrityRecord(
                digest=item.digest,
                content_type=item.content_type,
                size=item.size,
                file_present=file_present,
                digest_matches=bool(digest_matches),
            )
        )
    return integrity_rows


def _proposal_to_schema(row: ProposalORM) -> Proposal:
    provenance = None
    if row.analysis_backend:
        provenance = AnalysisProvenance(
            analysis_backend=row.analysis_backend,
            llm_provider=row.llm_provider,
            llm_model=row.llm_model,
            prompt_name=row.prompt_name,
            prompt_version=row.prompt_version,
        )
    return Proposal(
        proposal_id=row.proposal_id,
        entry_id=UUID(row.entry_id),
        validator_id=row.validator_id,
        action=ProposalAction(row.action),
        confidence=row.confidence,
        explanation=row.explanation,
        timestamp=row.timestamp,
        signature=row.signature,
        provenance=provenance,
    )


def _decision_to_schema(row: DecisionORM) -> Decision:
    return Decision(
        decision_id=row.decision_id,
        entry_id=UUID(row.entry_id),
        action=ProposalAction(row.action),
        timestamp=row.timestamp,
        supporting_proposals=[proposal.proposal_id for proposal in row.proposals],
        notes=row.notes,
    )


def _feedback_row_to_schema(
    row: EntryFeedback,
    storage: EvidenceStorage,
) -> FeedbackRecord:
    payload = storage.retrieve_bytes(row.digest)
    if payload is not None:
        try:
            decoded = json.loads(payload.decode("utf-8"))
            return FeedbackRecord.model_validate(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            pass

    matched_observables = []
    if row.matched_observables_json:
        matched_observables = json.loads(row.matched_observables_json)
    provenance = None
    if row.analysis_backend:
        provenance = AnalysisProvenance(
            analysis_backend=row.analysis_backend,
            llm_provider=row.llm_provider,
            llm_model=row.llm_model,
            prompt_name=row.prompt_name,
            prompt_version=row.prompt_version,
        )
    return FeedbackRecord(
        feedback_id=uuid5(
            UUID("00000000-0000-0000-0000-000000000000"),
            f"feedback:{row.entry_id}:{row.digest}:{row.feedback_id}",
        ),
        entry_id=UUID(row.entry_id),
        hashed_identifiers={},
        action_taken=row.action_taken or "",
        timestamp=row.timestamp,
        digest=row.digest,
        detection_kind=row.detection_kind,
        matched_observables=matched_observables,
        provenance=provenance,
    )
