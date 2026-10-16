from __future__ import annotations

from enum import StrEnum


class LifecycleState(StrEnum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    REVIEW = "review"
    DEPRECATED = "deprecated"


class ProposalAction(StrEnum):
    PROMOTE = "promote"
    RETAIN = "retain"
    REVIEW = "review"
    DEPRECATE = "deprecate"
