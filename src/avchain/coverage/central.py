"""Minimal central active/inactive demo. External coverage is SIMULATED only."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from avchain.auth.dependencies import require_ledger_key
from avchain.database.core import get_session
from avchain.evidence.storage import EvidenceStorage, store_evidence_item
from avchain.ledger.crud import list_entries
from avchain.models.enums import LifecycleState
from avchain.models.orm import CentralCheckEvent, Entry
from avchain.models.schemas import ThreatEntry
from avchain.utils.helpers import canonical_json_bytes, compute_sha256


class CheckEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: UUID
    entry_id: UUID
    active: bool
    reason: str = Field(min_length=1, max_length=500)
    source: Literal["SIMULATED_EXTERNAL_COVERAGE", "CENTRAL_REACTIVATION"]

    @model_validator(mode="after")
    def reactivation_is_active(self) -> CheckEvent:
        if self.source == "CENTRAL_REACTIVATION" and not self.active:
            raise ValueError("Reactivation must enable the check")
        return self


class CentralCheck(BaseModel):
    entry: ThreatEntry
    active: bool
    reason: str
    evidence_digest: str | None = None
    source: Literal["DEFAULT", "SIMULATED_EXTERNAL_COVERAGE", "CENTRAL_REACTIVATION"]


def apply_event(
    db: Session, storage: EvidenceStorage, event: CheckEvent
) -> dict[str, object]:
    raw = canonical_json_bytes(event.model_dump(mode="json"))
    digest = compute_sha256(raw)
    existing = (
        db.query(CentralCheckEvent).filter_by(event_id=str(event.event_id)).first()
    )
    if existing:
        if existing.evidence_digest != digest:
            raise ValueError("Event ID reused with different content")
        return {
            "event_id": existing.event_id,
            "replayed": True,
            "evidence_digest": digest,
        }
    entry = db.get(Entry, str(event.entry_id))
    if entry is None or entry.state != "confirmed":
        raise ValueError("Only a confirmed entry can be centrally controlled")
    try:
        item = store_evidence_item(
            db,
            storage,
            str(event.entry_id),
            raw,
            "application/json",
            purpose="central_check_event",
        )
        db.add(
            CentralCheckEvent(
                event_id=str(event.event_id),
                entry_id=str(event.entry_id),
                active=event.active,
                reason=event.reason,
                evidence_digest=item.digest,
            )
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(CentralCheckEvent).filter_by(event_id=str(event.event_id)).first()
        )
        if existing is None or existing.evidence_digest != digest:
            raise ValueError("Conflicting concurrent event") from None
        return {
            "event_id": existing.event_id,
            "replayed": True,
            "evidence_digest": digest,
        }
    return {
        "event_id": str(event.event_id),
        "replayed": False,
        "evidence_digest": digest,
    }


def central_checks(db: Session, storage: EvidenceStorage) -> list[CentralCheck]:
    result = []
    for entry in list_entries(db, LifecycleState.CONFIRMED):
        latest = (
            db.query(CentralCheckEvent)
            .filter_by(entry_id=str(entry.id))
            .order_by(CentralCheckEvent.sequence.desc())
            .first()
        )
        if latest is None:
            result.append(
                CentralCheck(
                    entry=entry,
                    active=True,
                    reason="No central deactivation",
                    source="DEFAULT",
                )
            )
            continue
        raw = storage.retrieve_bytes(latest.evidence_digest)
        if raw is None or compute_sha256(raw) != latest.evidence_digest:
            raise ValueError("Central coverage evidence integrity failure")
        event = CheckEvent.model_validate_json(raw)
        if (
            str(event.entry_id) != latest.entry_id
            or event.active != latest.active
            or event.reason != latest.reason
            or str(event.event_id) != latest.event_id
        ):
            raise ValueError("Central control disagrees with its evidence")
        result.append(
            CentralCheck(
                entry=entry,
                active=event.active,
                reason=event.reason,
                evidence_digest=latest.evidence_digest,
                source=event.source,
            )
        )
    return result


def central_router(storage: EvidenceStorage) -> APIRouter:
    router = APIRouter(prefix="/ledger/checks")

    @router.get("", response_model=list[CentralCheck])
    def checks(
        _: Annotated[str, Depends(require_ledger_key)],
        db: Annotated[Session, Depends(get_session)],
    ) -> list[CentralCheck]:
        try:
            return central_checks(db, storage)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/events")
    def event(
        payload: CheckEvent,
        _: Annotated[str, Depends(require_ledger_key)],
        db: Annotated[Session, Depends(get_session)],
    ) -> dict[str, object]:
        try:
            return apply_event(db, storage, payload)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    return router


class SimulatedExternalCoverage:
    """Data-only demo adapter. It never contacts a vendor or checks an installed AV."""

    def __init__(self, client: httpx.AsyncClient, api_key: str):
        self.client, self.api_key = client, api_key

    async def report(
        self, event_id: UUID, entry_id: UUID, *, covered: bool
    ) -> dict[str, object]:
        event = CheckEvent(
            event_id=event_id,
            entry_id=entry_id,
            active=not covered,
            reason="SIMULATED external feed: "
            + ("covered" if covered else "coverage withdrawn"),
            source="SIMULATED_EXTERNAL_COVERAGE",
        )
        response = await self.client.post(
            "/ledger/checks/events",
            json=event.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        response.raise_for_status()
        return dict(response.json())
