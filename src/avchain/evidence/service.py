from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from avchain.auth.dependencies import require_evidence_key
from avchain.database.core import get_session
from avchain.evidence.storage import (
    EvidenceStorage,
    encode_evidence_payload,
    get_evidence_item,
    list_evidence_items,
    store_evidence_item,
)
from avchain.models.orm import Entry
from avchain.models.schemas import EvidenceItem, EvidenceUploadRequest, FeedbackRecord
from avchain.utils.api import attach_api_contract_handlers

EvidenceAPIKey = Annotated[str, Depends(require_evidence_key)]
DBSession = Annotated[Session, Depends(get_session)]


def create_app(storage: EvidenceStorage | None = None) -> FastAPI:
    evidence_storage = storage or EvidenceStorage()
    app = FastAPI(title="LLM-AVChain Evidence Store", version="0.1.0")
    attach_api_contract_handlers(app)

    @app.post("/evidence", status_code=status.HTTP_201_CREATED)
    async def add_evidence(
        request: Request,
        _: EvidenceAPIKey,
        db: DBSession,
        entry_id: Annotated[str | None, Form()] = None,
        file: Annotated[UploadFile | None, File()] = None,
    ) -> dict[str, Any]:
        content_type = request.headers.get("content-type", "")
        resolved_entry_id = entry_id
        payload_bytes: bytes
        media_type: str
        data: Any = None

        if "multipart/form-data" in content_type:
            if file is None or resolved_entry_id is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="entry_id and file are required",
                )
            payload_bytes = await file.read()
            media_type = file.content_type or "application/octet-stream"
            data = _decode_json_payload(payload_bytes, media_type)
        else:
            if "application/json" not in content_type:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Unsupported content type",
                )
            body = await request.json()
            try:
                upload = EvidenceUploadRequest.model_validate(body)
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="JSON evidence must match {'entry_id': ..., 'data': ...}",
                ) from exc
            resolved_entry_id = str(upload.entry_id)
            media_type = request.headers.get("content-type", "application/json")
            data = upload.data
            payload_bytes = encode_evidence_payload(data=data, content_type=media_type)

        entry_exists = db.query(Entry).filter(Entry.id == resolved_entry_id).first()
        if entry_exists is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )

        evidence_item = store_evidence_item(
            db=db,
            storage=evidence_storage,
            entry_id=resolved_entry_id,
            data=payload_bytes,
            content_type=media_type,
            purpose=_resolve_evidence_purpose(entry_id=resolved_entry_id, data=data),
        )
        db.commit()
        return {
            "digest": evidence_item.digest,
            "size": evidence_item.size,
            "content_type": evidence_item.content_type,
        }

    @app.get("/health")
    def health(_: EvidenceAPIKey, db: DBSession) -> dict[str, object]:
        return {
            "service": "evidence",
            "status": "ok",
            "entries": db.query(Entry).count(),
        }

    @app.get("/evidence/{digest}")
    def fetch_evidence(digest: str, _: EvidenceAPIKey, db: DBSession) -> Response:
        evidence_item = get_evidence_item(db=db, digest=digest)
        if evidence_item is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Evidence not found",
            )
        payload = evidence_storage.retrieve_bytes(digest)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Evidence file not found",
            )
        return Response(
            content=payload,
            media_type=evidence_item.content_type,
            headers={"Content-Disposition": f'attachment; filename="{digest}"'},
        )

    @app.get("/evidence/entries/{entry_id}", response_model=list[EvidenceItem])
    def get_entry_evidence(
        entry_id: str,
        _: EvidenceAPIKey,
        db: DBSession,
    ) -> list[EvidenceItem]:
        entry_exists = db.query(Entry).filter(Entry.id == entry_id).first()
        if entry_exists is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        return list_evidence_items(db=db, entry_id=entry_id)

    return app


def _resolve_evidence_purpose(entry_id: str, data: Any) -> str:
    try:
        feedback = FeedbackRecord.model_validate(data)
    except Exception:
        return "supporting"
    if str(feedback.entry_id) != entry_id:
        return "supporting"
    return "feedback"


def _decode_json_payload(payload_bytes: bytes, media_type: str) -> Any:
    if media_type != "application/json":
        return None
    try:
        return json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


app = create_app()
