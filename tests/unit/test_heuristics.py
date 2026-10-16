from __future__ import annotations

from avchain.models.enums import ProposalAction
from avchain.validator.heuristics import DeterministicHeuristic


def test_heuristic_promotes_when_signal_is_strong() -> None:
    heuristic = DeterministicHeuristic()
    action, confidence, _ = heuristic.analyze(
        observables=["malware-hash-a"],
        evidence_data=[b'{"label":"malicious"}'],
    )
    assert action == ProposalAction.PROMOTE
    assert confidence >= 0.75


def test_heuristic_deprecates_when_signal_is_weak() -> None:
    heuristic = DeterministicHeuristic()
    action, confidence, _ = heuristic.analyze(
        observables=["benign-hash-1"], evidence_data=[]
    )
    assert action == ProposalAction.DEPRECATE
    assert confidence <= 0.35
