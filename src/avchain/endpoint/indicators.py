from __future__ import annotations

from collections.abc import Mapping, Set
from types import MappingProxyType
from uuid import UUID


class ExactIndicatorIndex:
    """Immutable catalog snapshot with the original first-entry match order."""

    def __init__(self, entries: Mapping[UUID, Set[str]]) -> None:
        self.entries: Mapping[UUID, frozenset[str]] = MappingProxyType(
            {entry_id: frozenset(values) for entry_id, values in entries.items()}
        )
        self._first: dict[str, tuple[int, UUID]] = {}
        for position, (entry_id, observables) in enumerate(self.entries.items()):
            for observable in observables:
                self._first.setdefault(observable, (position, entry_id))

    def first(self, observable: str) -> tuple[int, UUID] | None:
        """Do not normalize: matching remains exact and case-sensitive."""
        return self._first.get(observable)
