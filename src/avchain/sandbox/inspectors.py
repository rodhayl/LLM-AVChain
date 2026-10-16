from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from avchain.attack import derive_attack_techniques
from avchain.utils.helpers import compute_sha256

SUSPICIOUS_STRINGS = {
    "behavior:postinstall": ("postinstall",),
    "behavior:powershell-download": (
        "powershell",
        "invoke-webrequest",
        "downloadstring",
        "frombase64string",
    ),
    "behavior:suspicious-network": ("http://", "https://", "curl ", "wget "),
}


@dataclass(slots=True)
class SandboxInspection:
    root: str
    artifact_count: int
    digests: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    summary: str = ""


def inspect_path(path: str | Path) -> SandboxInspection:
    target = Path(path)
    if target.is_dir():
        return inspect_bundle(target)
    raw_bytes = target.read_bytes()
    indicators = _indicators_for_file(target, raw_bytes)
    return SandboxInspection(
        root=str(target),
        artifact_count=1,
        digests=[compute_sha256(raw_bytes)],
        indicators=indicators,
        attack_techniques=derive_attack_techniques(*indicators),
        summary=f"Static inspection of {target.name}",
    )


def inspect_bundle(root: str | Path) -> SandboxInspection:
    bundle_root = Path(root)
    digests: list[str] = []
    indicators: list[str] = []
    artifact_count = 0
    for path in sorted(bundle_root.rglob("*")):
        if not path.is_file():
            continue
        artifact_count += 1
        raw_bytes = path.read_bytes()
        digests.append(compute_sha256(raw_bytes))
        for indicator in _indicators_for_file(path, raw_bytes):
            if indicator not in indicators:
                indicators.append(indicator)
    return SandboxInspection(
        root=str(bundle_root),
        artifact_count=artifact_count,
        digests=digests,
        indicators=indicators,
        attack_techniques=derive_attack_techniques(*indicators),
        summary=f"Static bundle inspection of {bundle_root.name}",
    )


def _indicators_for_file(path: Path, raw_bytes: bytes) -> list[str]:
    indicators: list[str] = []
    text_payload = raw_bytes.decode("utf-8", errors="ignore").lower()
    if path.name == "package.json":
        indicators.extend(_package_indicators(raw_bytes))
    for indicator, markers in SUSPICIOUS_STRINGS.items():
        matches = any(marker in text_payload for marker in markers)
        if matches and indicator not in indicators:
            indicators.append(indicator)
    return indicators


def _package_indicators(raw_bytes: bytes) -> list[str]:
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    indicators: list[str] = []
    package_name = payload.get("name")
    if isinstance(package_name, str) and package_name:
        indicators.append(f"package:{package_name}")
    scripts = payload.get("scripts")
    if isinstance(scripts, dict) and "postinstall" in scripts:
        indicators.append("behavior:postinstall")
    return indicators
