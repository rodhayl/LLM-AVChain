from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from avchain.models.enums import LifecycleState, ProposalAction
from avchain.models.schemas import (
    CoverageReport,
    Proposal,
    ThreatEntry,
    ThreatEntryCreate,
)


def test_threat_entry_defaults() -> None:
    entry = ThreatEntry(observables=["ioc-1"])
    assert entry.state == LifecycleState.SUSPECTED
    assert entry.evidence_digests == []
    assert entry.history == []


def test_threat_entry_create_accepts_inline_evidence() -> None:
    payload = ThreatEntryCreate(
        observables=["ioc-1"],
        evidence=[{"content_type": "application/json", "data": {"value": "x"}}],
        attack_techniques=["T1059"],
    )
    assert payload.attack_techniques == ["T1059"]
    assert payload.evidence[0].content_type == "application/json"


def test_proposal_confidence_is_bounded() -> None:
    with pytest.raises(ValidationError):
        Proposal(
            proposal_id="proposal-1",
            entry_id="b9c2a239-6d1b-4f38-95e7-f9dcee05a6c3",
            validator_id="validator1",
            action=ProposalAction.PROMOTE,
            confidence=1.5,
            explanation="too confident",
            timestamp=datetime(2026, 4, 9, tzinfo=UTC),
            signature="sig",
        )


def test_proposal_timestamp_is_required() -> None:
    with pytest.raises(ValidationError):
        Proposal(
            proposal_id="proposal-1",
            entry_id="b9c2a239-6d1b-4f38-95e7-f9dcee05a6c3",
            validator_id="validator1",
            action=ProposalAction.PROMOTE,
            confidence=0.5,
            explanation="missing timestamp",
            signature="sig",
        )


def test_coverage_report_timestamp_is_required() -> None:
    with pytest.raises(ValidationError):
        CoverageReport(
            entry_id="b9c2a239-6d1b-4f38-95e7-f9dcee05a6c3",
            vendor="VendorA",
            detected=True,
        )
