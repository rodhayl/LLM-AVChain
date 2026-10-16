from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, Protocol
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from avchain.auth.dependencies import require_consensus_key
from avchain.config.settings import get_settings
from avchain.consensus.registry import ValidatorRegistry, get_registry
from avchain.crypto.keys import canonicalize, load_public_key, verify_signature
from avchain.database.core import get_session
from avchain.models.enums import LifecycleState, ProposalAction
from avchain.models.orm import Decision as DecisionORM
from avchain.models.orm import DecisionEpoch, Entry
from avchain.models.orm import Proposal as ProposalORM
from avchain.models.schemas import (
    AnalysisProvenance,
    Decision,
    Proposal,
    ReviewRequest,
    StateTransition,
)
from avchain.utils.api import attach_api_contract_handlers
from avchain.utils.helpers import derive_proposal_id

ConsensusAPIKey = Annotated[str, Depends(require_consensus_key)]
DBSession = Annotated[Session, Depends(get_session)]


class LedgerGateway(Protocol):
    async def transition_entry(
        self,
        entry_id: str,
        transition: StateTransition,
    ) -> dict[str, Any]: ...


@dataclass
class HttpLedgerGateway:
    base_url: str
    api_key: str

    async def transition_entry(
        self,
        entry_id: str,
        transition: StateTransition,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(base_url=self.base_url, timeout=10.0) as client:
            response = await client.post(
                f"/ledger/entries/{entry_id}/transitions",
                json=transition.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
        response.raise_for_status()
        response_payload = response.json()
        return dict(response_payload)


def create_app(
    ledger_gateway: LedgerGateway | None = None,
    registry: ValidatorRegistry | None = None,
) -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="LLM-AVChain Consensus Controller", version="0.1.0")
    attach_api_contract_handlers(app)
    app.state.ledger_gateway = ledger_gateway or HttpLedgerGateway(
        base_url=settings.ledger_base_url,
        api_key=settings.ledger_api_key,
    )
    app.state.registry = registry or get_registry()

    @app.post("/consensus/proposals", status_code=status.HTTP_201_CREATED)
    async def submit_proposal(
        proposal: Proposal,
        _: ConsensusAPIKey,
        db: DBSession,
    ) -> dict[str, Any]:
        validator = app.state.registry.get(proposal.validator_id)
        if validator is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unknown validator",
            )

        unsigned_payload = proposal.model_dump(
            mode="json",
            exclude={"signature"},
            exclude_none=True,
        )
        canonical = canonicalize(unsigned_payload)
        public_key = load_public_key(validator.public_key)
        if not verify_signature(public_key, canonical, proposal.signature):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid signature",
            )

        entry = db.query(Entry).filter(Entry.id == str(proposal.entry_id)).first()
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        expected_proposal_id = derive_proposal_id(
            entry_id=str(proposal.entry_id),
            validator_id=proposal.validator_id,
            timestamp=proposal.timestamp,
        )
        if proposal.proposal_id != expected_proposal_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="proposal_id does not match derived value",
            )

        existing = db.get(ProposalORM, proposal.proposal_id)
        if existing is None:
            db.add(
                ProposalORM(
                    proposal_id=proposal.proposal_id,
                    entry_id=str(proposal.entry_id),
                    validator_id=proposal.validator_id,
                    action=proposal.action.value,
                    confidence=proposal.confidence,
                    explanation=proposal.explanation,
                    timestamp=proposal.timestamp,
                    signature=proposal.signature,
                    analysis_backend=(
                        proposal.provenance.analysis_backend
                        if proposal.provenance is not None
                        else None
                    ),
                    llm_provider=(
                        proposal.provenance.llm_provider
                        if proposal.provenance is not None
                        else None
                    ),
                    llm_model=(
                        proposal.provenance.llm_model
                        if proposal.provenance is not None
                        else None
                    ),
                    prompt_name=(
                        proposal.provenance.prompt_name
                        if proposal.provenance is not None
                        else None
                    ),
                    prompt_version=(
                        proposal.provenance.prompt_version
                        if proposal.provenance is not None
                        else None
                    ),
                )
            )
            db.commit()

        decision = await _evaluate_quorum(
            db=db,
            entry_id=str(proposal.entry_id),
            registry=app.state.registry,
            ledger_gateway=app.state.ledger_gateway,
        )
        if decision is None:
            return {"status": "queued"}
        return {"status": "accepted", "decision": decision.model_dump(mode="json")}

    @app.get("/health")
    def health(_: ConsensusAPIKey, db: DBSession) -> dict[str, object]:
        return {
            "service": "consensus",
            "status": "ok",
            "validators": app.state.registry.count,
            "proposals": db.query(ProposalORM).count(),
            "decisions": db.query(DecisionORM).count(),
        }

    @app.post("/consensus/review_requests")
    async def request_review(
        payload: ReviewRequest,
        _: ConsensusAPIKey,
        db: DBSession,
    ) -> dict[str, Any]:
        entry = db.query(Entry).filter(Entry.id == str(payload.entry_id)).first()
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        if LifecycleState(entry.state) != LifecycleState.CONFIRMED:
            return {"status": "ignored"}

        transition = StateTransition(
            from_state=LifecycleState.CONFIRMED,
            to_state=LifecycleState.REVIEW,
            actor="oracle",
            proposal_ids=[],
            notes=payload.reason,
        )
        try:
            result = await app.state.ledger_gateway.transition_entry(
                str(payload.entry_id),
                transition,
            )
            return dict(result)
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc

    @app.get("/consensus/decisions/{entry_id}", response_model=list[Decision])
    def get_decisions(
        entry_id: str,
        _: ConsensusAPIKey,
        db: DBSession,
    ) -> list[Decision]:
        decisions = (
            db.query(DecisionORM)
            .filter(DecisionORM.entry_id == entry_id)
            .order_by(DecisionORM.timestamp.asc())
            .all()
        )
        return [_decision_to_schema(decision) for decision in decisions]

    @app.get("/consensus/proposals/{entry_id}", response_model=list[Proposal])
    def get_proposals(
        entry_id: str,
        _: ConsensusAPIKey,
        db: DBSession,
    ) -> list[Proposal]:
        proposals = (
            db.query(ProposalORM)
            .filter(ProposalORM.entry_id == entry_id)
            .order_by(ProposalORM.timestamp.asc())
            .all()
        )
        return [_proposal_to_schema(proposal) for proposal in proposals]

    return app


async def _evaluate_quorum(
    db: Session,
    entry_id: str,
    registry: ValidatorRegistry,
    ledger_gateway: LedgerGateway,
) -> Decision | None:
    entry = db.query(Entry).filter(Entry.id == entry_id).first()
    if entry is None or registry.count == 0:
        return None

    proposals = (
        db.query(ProposalORM)
        .filter(ProposalORM.entry_id == entry_id)
        .filter(ProposalORM.timestamp >= entry.updated_at)
        .order_by(ProposalORM.timestamp.asc())
        .all()
    )
    latest_by_validator: dict[str, ProposalORM] = {}
    for proposal in proposals:
        latest_by_validator[proposal.validator_id] = proposal
    active_proposals = list(latest_by_validator.values())
    if not active_proposals:
        return None

    buckets: dict[ProposalAction, list[ProposalORM]] = {}
    for proposal in active_proposals:
        buckets.setdefault(ProposalAction(proposal.action), []).append(proposal)

    threshold = registry.majority_threshold()
    current_state = LifecycleState(entry.state)
    winning_action: ProposalAction | None = None
    supporting: list[ProposalORM] = []

    if current_state in {LifecycleState.SUSPECTED, LifecycleState.REVIEW}:
        promote_votes = buckets.get(ProposalAction.PROMOTE, [])
        if len(promote_votes) >= threshold:
            average_confidence = sum(item.confidence for item in promote_votes) / len(
                promote_votes
            )
            if average_confidence >= 0.5:
                winning_action = ProposalAction.PROMOTE
                supporting = promote_votes
        if winning_action is None:
            deprecate_votes = buckets.get(ProposalAction.DEPRECATE, [])
            if len(deprecate_votes) >= threshold:
                winning_action = ProposalAction.DEPRECATE
                supporting = deprecate_votes
    elif current_state == LifecycleState.CONFIRMED:
        review_votes = buckets.get(ProposalAction.REVIEW, [])
        if len(review_votes) >= threshold:
            winning_action = ProposalAction.REVIEW
            supporting = review_votes

    if winning_action is None:
        return None

    target_state = _target_state_for_action(current_state, winning_action)
    if target_state is None:
        return None

    decision_notes = (
        f"Quorum reached with {len(supporting)}/{registry.count} validators"
    )
    epoch_key = _decision_epoch_key(
        entry_id=entry_id,
        source_state=current_state,
        target_state=target_state,
        state_updated_at=entry.updated_at,
    )
    existing_epoch = db.get(DecisionEpoch, epoch_key)
    if existing_epoch is not None:
        if existing_epoch.decision_id is None:
            return None
        existing_decision = db.get(DecisionORM, existing_epoch.decision_id)
        if existing_decision is None:
            return None
        return _decision_to_schema(existing_decision)

    epoch = DecisionEpoch(
        epoch_key=epoch_key,
        entry_id=entry_id,
        source_state=current_state.value,
        target_state=target_state.value,
        state_updated_at=entry.updated_at,
    )
    db.add(epoch)
    try:
        db.flush()
        db.commit()
    except IntegrityError:
        db.rollback()
        claimed_epoch = db.get(DecisionEpoch, epoch_key)
        if claimed_epoch is None or claimed_epoch.decision_id is None:
            return None
        claimed_decision = db.get(DecisionORM, claimed_epoch.decision_id)
        if claimed_decision is None:
            return None
        return _decision_to_schema(claimed_decision)

    transition = StateTransition(
        from_state=current_state,
        to_state=target_state,
        actor="consensus",
        proposal_ids=[proposal.proposal_id for proposal in supporting],
        notes=decision_notes,
    )
    try:
        await ledger_gateway.transition_entry(entry_id, transition)
    except httpx.HTTPError as exc:
        claimed_epoch = db.get(DecisionEpoch, epoch_key)
        if claimed_epoch is not None and claimed_epoch.decision_id is None:
            db.delete(claimed_epoch)
            db.commit()
        else:
            db.rollback()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc

    epoch_marker = db.get(DecisionEpoch, epoch_key)
    if epoch_marker is None:
        return None
    decision = DecisionORM(
        entry_id=entry_id,
        action=winning_action.value,
        notes=decision_notes,
    )
    db.add(decision)
    db.flush()
    decision.proposals.extend(supporting)
    epoch_marker.decision_id = decision.decision_id
    db.commit()
    db.refresh(decision)
    return _decision_to_schema(decision)


def _decision_to_schema(decision: DecisionORM) -> Decision:
    return Decision(
        decision_id=decision.decision_id,
        entry_id=UUID(decision.entry_id),
        action=ProposalAction(decision.action),
        timestamp=decision.timestamp,
        supporting_proposals=[proposal.proposal_id for proposal in decision.proposals],
        notes=decision.notes,
    )


def _proposal_to_schema(proposal: ProposalORM) -> Proposal:
    provenance = None
    if proposal.analysis_backend:
        provenance = AnalysisProvenance(
            analysis_backend=proposal.analysis_backend,
            llm_provider=proposal.llm_provider,
            llm_model=proposal.llm_model,
            prompt_name=proposal.prompt_name,
            prompt_version=proposal.prompt_version,
        )
    return Proposal(
        proposal_id=proposal.proposal_id,
        entry_id=UUID(proposal.entry_id),
        validator_id=proposal.validator_id,
        action=ProposalAction(proposal.action),
        confidence=proposal.confidence,
        explanation=proposal.explanation,
        timestamp=proposal.timestamp,
        signature=proposal.signature,
        provenance=provenance,
    )


def _target_state_for_action(
    current_state: LifecycleState,
    action: ProposalAction,
) -> LifecycleState | None:
    mapping = {
        (LifecycleState.SUSPECTED, ProposalAction.PROMOTE): LifecycleState.CONFIRMED,
        (LifecycleState.SUSPECTED, ProposalAction.DEPRECATE): LifecycleState.DEPRECATED,
        (LifecycleState.REVIEW, ProposalAction.PROMOTE): LifecycleState.CONFIRMED,
        (LifecycleState.REVIEW, ProposalAction.DEPRECATE): LifecycleState.DEPRECATED,
        (LifecycleState.CONFIRMED, ProposalAction.REVIEW): LifecycleState.REVIEW,
    }
    return mapping.get((current_state, action))


def _decision_epoch_key(
    entry_id: str,
    source_state: LifecycleState,
    target_state: LifecycleState,
    state_updated_at: Any,
) -> str:
    return (
        f"{entry_id}:{source_state.value}:{target_state.value}:"
        f"{state_updated_at.isoformat()}"
    )


app = create_app()
