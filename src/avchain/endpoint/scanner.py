from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from avchain.endpoint.indicators import ExactIndicatorIndex
from avchain.utils.helpers import compute_sha256

SUSPICIOUS_MARKERS = {
    "behavior:postinstall": ("postinstall",),
    "behavior:powershell-download": (
        "powershell",
        "invoke-webrequest",
        "frombase64string",
        "downloadstring",
    ),
    "behavior:suspicious-network": ("http://", "https://", "curl ", "wget "),
}


@dataclass(slots=True)
class ArtifactScan:
    path: Path
    digest: str
    matched_observables: list[str]
    detection_kind: str
    summary: str
    metadata: dict[str, Any]


def scan_artifact(path: Path, entry_observables: set[str]) -> ArtifactScan | None:
    raw_bytes = path.read_bytes()
    digest = compute_sha256(raw_bytes)
    if digest in entry_observables:
        return ArtifactScan(
            path=path,
            digest=digest,
            matched_observables=[digest],
            detection_kind="direct",
            summary=f"Direct digest match for {path.name}",
            metadata={"artifact_name": path.name, "artifact_type": "file"},
        )

    contextual_matches = _contextual_matches(path, raw_bytes, entry_observables)
    if not contextual_matches:
        return None
    return ArtifactScan(
        path=path,
        digest=digest,
        matched_observables=contextual_matches,
        detection_kind="contextual",
        summary=f"Contextual suspicious package/script indicators for {path.name}",
        metadata={"artifact_name": path.name, "artifact_type": "contextual"},
    )


def _contextual_matches(
    path: Path,
    raw_bytes: bytes,
    entry_observables: set[str],
) -> list[str]:
    return sorted(_contextual_indicators(path, raw_bytes) & entry_observables)


def scan_indexed_artifact(
    path: Path, index: ExactIndicatorIndex
) -> tuple[UUID, ArtifactScan] | None:
    """Read/hash once per artifact event, retaining catalog-order precedence.

    No file content or digest survives this call. Detectable changes during the
    scan raise an error rather than returning a result from a stale snapshot.
    """
    if not index.entries:
        return None
    identity = _file_identity(path)
    raw_bytes = path.read_bytes()
    digest = compute_sha256(raw_bytes)
    direct = index.first(digest)
    contextual: set[str] = set()
    winner = direct
    # A direct match in the first entry used to return without parsing context.
    # Otherwise an earlier contextual entry must still beat a later digest hit.
    if direct is None or direct[0] != 0:
        contextual = _contextual_indicators(path, raw_bytes)
        for observable in contextual:
            candidate = index.first(observable)
            if candidate is not None and (winner is None or candidate[0] < winner[0]):
                winner = candidate
    if _file_identity(path) != identity or len(raw_bytes) != identity[2]:
        raise OSError("Artifact changed during scan")
    if winner is None:
        return None
    entry_id = winner[1]
    is_direct = digest in index.entries[entry_id]
    return entry_id, ArtifactScan(
        path=path,
        digest=digest,
        matched_observables=(
            [digest] if is_direct else sorted(contextual & index.entries[entry_id])
        ),
        detection_kind="direct" if is_direct else "contextual",
        summary=(
            f"Direct digest match for {path.name}"
            if is_direct
            else f"Contextual suspicious package/script indicators for {path.name}"
        ),
        metadata={
            "artifact_name": path.name,
            "artifact_type": "file" if is_direct else "contextual",
        },
    )


def _file_identity(path: Path) -> tuple[int, int, int, int, int]:
    info = path.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _contextual_indicators(path: Path, raw_bytes: bytes) -> set[str]:
    derived_observables: set[str] = set()
    if path.name == "package.json":
        derived_observables.update(_package_indicators(path, raw_bytes))
    text_payload = raw_bytes.decode("utf-8", errors="ignore").lower()
    for observable, markers in SUSPICIOUS_MARKERS.items():
        if any(marker in text_payload for marker in markers):
            derived_observables.add(observable)
    return derived_observables


def _package_indicators(path: Path, raw_bytes: bytes) -> set[str]:
    try:
        package_payload = json.loads(raw_bytes.decode("utf-8"))
    except json.JSONDecodeError:
        return set()
    if not isinstance(package_payload, dict):
        return set()
    indicators: set[str] = set()
    package_name = package_payload.get("name")
    if isinstance(package_name, str) and package_name:
        indicators.add(f"package:{package_name}")

    scripts = package_payload.get("scripts", {})
    if isinstance(scripts, dict) and "postinstall" in scripts:
        indicators.add("behavior:postinstall")

    for sibling in path.parent.rglob("*"):
        if not sibling.is_file() or sibling == path or sibling.stat().st_size > 65536:
            continue
        sibling_text = sibling.read_text(encoding="utf-8", errors="ignore").lower()
        for observable, markers in SUSPICIOUS_MARKERS.items():
            if any(marker in sibling_text for marker in markers):
                indicators.add(observable)
    return indicators
