from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Protocol
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session

from avchain.auth.dependencies import require_coverage_key
from avchain.config.settings import get_settings
from avchain.database.core import get_session
from avchain.models.enums import LifecycleState
from avchain.models.orm import CoverageReportORM, Entry
from avchain.models.schemas import CoverageMetric, CoverageReport, ReviewRequest
from avchain.utils.api import attach_api_contract_handlers

CoverageAPIKey = Annotated[str, Depends(require_coverage_key)]
DBSession = Annotated[Session, Depends(get_session)]


class ConsensusGateway(Protocol):
    async def request_review(self, entry_id: str, reason: str) -> dict[str, Any]: ...


@dataclass
class HttpConsensusGateway:
    base_url: str
    api_key: str

    async def request_review(self, entry_id: str, reason: str) -> dict[str, Any]:
        payload = ReviewRequest(entry_id=UUID(entry_id), reason=reason)
        async with httpx.AsyncClient(base_url=self.base_url, timeout=10.0) as client:
            response = await client.post(
                "/consensus/review_requests",
                json=payload.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
        response.raise_for_status()
        response_payload = response.json()
        return dict(response_payload)


def create_app(consensus_gateway: ConsensusGateway | None = None) -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="LLM-AVChain Coverage Oracle", version="0.1.0")
    attach_api_contract_handlers(app)
    app.state.consensus_gateway = consensus_gateway or HttpConsensusGateway(
        base_url=settings.consensus_base_url,
        api_key=settings.consensus_api_key,
    )

    @app.post(
        "/coverage/reports",
        response_model=CoverageMetric,
        status_code=status.HTTP_201_CREATED,
    )
    async def submit_report(
        payload: CoverageReport,
        _: CoverageAPIKey,
        db: DBSession,
    ) -> CoverageMetric:
        entry = db.query(Entry).filter(Entry.id == str(payload.entry_id)).first()
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )

        db.add(
            CoverageReportORM(
                report_id=str(payload.report_id),
                entry_id=str(payload.entry_id),
                vendor=payload.vendor,
                detected=payload.detected,
                timestamp=payload.timestamp,
            )
        )
        db.commit()

        metric = compute_metric(db=db, entry_id=str(payload.entry_id))
        if (
            metric.vendors_total >= 3
            and metric.coverage_ratio > settings.coverage_threshold
            and LifecycleState(entry.state) == LifecycleState.CONFIRMED
        ):
            try:
                await app.state.consensus_gateway.request_review(
                    entry_id=str(payload.entry_id),
                    reason="coverage_threshold_exceeded",
                )
            except httpx.HTTPError as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=str(exc),
                ) from exc
        return metric

    @app.get("/health")
    def health(_: CoverageAPIKey, db: DBSession) -> dict[str, object]:
        return {
            "service": "coverage",
            "status": "ok",
            "reports": db.query(CoverageReportORM).count(),
        }

    @app.get("/coverage/metrics/{entry_id}", response_model=CoverageMetric)
    def get_metric(entry_id: str, _: CoverageAPIKey, db: DBSession) -> CoverageMetric:
        if db.query(Entry).filter(Entry.id == entry_id).first() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        return compute_metric(db=db, entry_id=entry_id)

    return app


def compute_metric(db: Session, entry_id: str) -> CoverageMetric:
    reports = (
        db.query(CoverageReportORM)
        .filter(CoverageReportORM.entry_id == entry_id)
        .order_by(CoverageReportORM.timestamp.asc())
        .all()
    )
    latest_by_vendor: dict[str, CoverageReportORM] = {}
    for report in reports:
        latest_by_vendor[report.vendor] = report

    vendors_total = len(latest_by_vendor)
    vendors_detected = sum(1 for report in latest_by_vendor.values() if report.detected)
    ratio = vendors_detected / vendors_total if vendors_total else 0.0

    # The shipped POC requires a minimum sample size of three vendors before a
    # high coverage ratio can trigger review, matching the documented demo flow.
    return CoverageMetric(
        entry_id=UUID(entry_id),
        vendors_total=vendors_total,
        vendors_detected=vendors_detected,
        coverage_ratio=ratio,
        timestamp=datetime.now(UTC),
    )


app = create_app()
