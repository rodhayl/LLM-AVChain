from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from avchain.utils.helpers import ensure_directory


@dataclass(slots=True)
class RemediationResult:
    action_taken: str
    quarantine_path: str | None = None


def apply_remediation(
    artifact_path: Path,
    *,
    action: str,
    quarantine_dir: str | Path,
) -> RemediationResult:
    action_name = action.lower()
    if action_name in {"log", "alert"}:
        return RemediationResult(action_taken=action_name)

    quarantine_root = ensure_directory(quarantine_dir)
    target_path = quarantine_root / artifact_path.name
    if action_name == "simulate_quarantine":
        shutil.copy2(artifact_path, target_path)
        return RemediationResult(
            action_taken="simulate_quarantine",
            quarantine_path=str(target_path),
        )
    if action_name == "quarantine":
        shutil.move(str(artifact_path), str(target_path))
        return RemediationResult(
            action_taken="quarantine",
            quarantine_path=str(target_path),
        )
    if action_name == "block_execution":
        return RemediationResult(action_taken="block_execution")
    return RemediationResult(action_taken="log")
