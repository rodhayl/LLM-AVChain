from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from avchain.auth.dependencies import require_ledger_key
from avchain.consensus.registry import get_registry
from avchain.database.core import get_session
from avchain.evidence.storage import EvidenceStorage
from avchain.incident.knowledge import KnowledgeStore
from avchain.incident.models import SignedPackage, SignedRevocation

Auth = Annotated[str, Depends(require_ledger_key)]
DB = Annotated[Session, Depends(get_session)]


def knowledge_router(storage: EvidenceStorage) -> APIRouter:
    router = APIRouter(prefix="/ledger/remediation")

    @router.post("/packages", response_model=SignedPackage, status_code=201)
    def publish(payload: SignedPackage, _: Auth, db: DB) -> SignedPackage:
        try:
            return KnowledgeStore(db, storage, get_registry()).publish(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.get("/packages/{package_id}", response_model=SignedPackage)
    def latest(
        package_id: str, _: Auth, db: DB, minimum_version: int = 1
    ) -> SignedPackage:
        try:
            return KnowledgeStore(db, storage, get_registry()).latest(
                package_id, minimum_version=minimum_version
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/revocations", status_code=201)
    def revoke(payload: SignedRevocation, _: Auth, db: DB) -> dict[str, str]:
        try:
            KnowledgeStore(db, storage, get_registry()).revoke(payload)
            return {"status": "revoked"}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return router
