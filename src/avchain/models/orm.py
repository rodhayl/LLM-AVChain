from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


decision_proposals = Table(
    "decision_proposals",
    Base.metadata,
    Column("decision_id", String, ForeignKey("decisions.decision_id")),
    Column("proposal_id", String, ForeignKey("proposals.proposal_id")),
)


class Entry(Base):
    __tablename__ = "entries"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    observables_json: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(32), default="suspected")
    attack_techniques_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    tlp_label: Mapped[str] = mapped_column(String(32), default="TLP:CLEAR")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    events: Mapped[list[EntryEvent]] = relationship(
        back_populates="entry",
        cascade="all, delete-orphan",
        order_by="EntryEvent.timestamp",
        lazy="selectin",
    )
    evidence_links: Mapped[list[EntryEvidenceLink]] = relationship(
        back_populates="entry",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    feedback_items: Mapped[list[EntryFeedback]] = relationship(
        back_populates="entry",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class EntryEvent(Base):
    __tablename__ = "entry_events"

    event_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entry_id: Mapped[str] = mapped_column(String(36), ForeignKey("entries.id"))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(64))
    proposal_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    entry: Mapped[Entry] = relationship(back_populates="events")


class EvidenceObject(Base):
    __tablename__ = "evidence_objects"

    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Legacy denormalized first-link pointer retained for backwards-compatible
    # SQLite bootstrap behavior. EntryEvidenceLink is the authoritative
    # association model for evidence ownership and sharing.
    entry_id: Mapped[str] = mapped_column(String(36), ForeignKey("entries.id"))
    purpose: Mapped[str] = mapped_column(String(32), default="supporting")
    content_type: Mapped[str] = mapped_column(String(128))
    size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    links: Mapped[list[EntryEvidenceLink]] = relationship(
        back_populates="evidence_item",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class EntryEvidenceLink(Base):
    __tablename__ = "entry_evidence"

    entry_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("entries.id"),
        primary_key=True,
    )
    digest: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("evidence_objects.digest"),
        primary_key=True,
    )

    entry: Mapped[Entry] = relationship(back_populates="evidence_links")
    evidence_item: Mapped[EvidenceObject] = relationship(back_populates="links")


class EntryFeedback(Base):
    __tablename__ = "entry_feedback"

    feedback_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )
    entry_id: Mapped[str] = mapped_column(String(36), ForeignKey("entries.id"))
    digest: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("evidence_objects.digest"),
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    action_taken: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detection_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    matched_observables_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    analysis_backend: Mapped[str | None] = mapped_column(String(64), nullable=True)
    llm_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    llm_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    endpoint_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    endpoint_signature_valid: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    entry: Mapped[Entry] = relationship(back_populates="feedback_items")


class Proposal(Base):
    __tablename__ = "proposals"

    proposal_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    entry_id: Mapped[str] = mapped_column(String(36), ForeignKey("entries.id"))
    validator_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(Float)
    explanation: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    signature: Mapped[str] = mapped_column(Text)
    analysis_backend: Mapped[str | None] = mapped_column(String(64), nullable=True)
    llm_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    llm_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Decision(Base):
    __tablename__ = "decisions"

    decision_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    entry_id: Mapped[str] = mapped_column(String(36), ForeignKey("entries.id"))
    action: Mapped[str] = mapped_column(String(32))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    proposals: Mapped[list[Proposal]] = relationship(
        secondary=decision_proposals,
        lazy="selectin",
    )


class DecisionEpoch(Base):
    __tablename__ = "decision_epochs"

    epoch_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    entry_id: Mapped[str] = mapped_column(String(36), ForeignKey("entries.id"))
    source_state: Mapped[str] = mapped_column(String(32))
    target_state: Mapped[str] = mapped_column(String(32))
    state_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decision_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("decisions.decision_id"),
        nullable=True,
        unique=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class CoverageReportORM(Base):
    __tablename__ = "coverage_reports"

    report_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    entry_id: Mapped[str] = mapped_column(String(36), ForeignKey("entries.id"))
    vendor: Mapped[str] = mapped_column(String(128))
    detected: Mapped[bool] = mapped_column(Boolean)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class ReviewRecordORM(Base):
    __tablename__ = "review_records"

    review_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    entry_id: Mapped[str] = mapped_column(String(36), ForeignKey("entries.id"))
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open")
    requested_by: Mapped[str] = mapped_column(String(64))
    assigned_to: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resolution_action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class ReviewNoteORM(Base):
    __tablename__ = "review_notes"

    note_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )
    review_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("review_records.review_id"),
    )
    author: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


class RemediationPackageORM(Base):
    __tablename__ = "remediation_packages"
    package_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    entry_id: Mapped[str] = mapped_column(String(36), ForeignKey("entries.id"))
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    envelope_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class RemediationRevocationORM(Base):
    __tablename__ = "remediation_revocations"
    package_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    envelope_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class CentralCheckEvent(Base):
    """Append-only demo control events; IOC data stays in the existing entries."""

    __tablename__ = "central_check_events"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True)
    entry_id: Mapped[str] = mapped_column(String(36), ForeignKey("entries.id"))
    active: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(String(500))
    evidence_digest: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
