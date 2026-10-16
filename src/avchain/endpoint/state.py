from __future__ import annotations


class EndpointArtifactState:
    def __init__(self) -> None:
        self._processed_artifacts: set[str] = set()

    def has_processed(self, fingerprint: str) -> bool:
        return fingerprint in self._processed_artifacts

    def mark_processed(self, fingerprint: str) -> None:
        self._processed_artifacts.add(fingerprint)
