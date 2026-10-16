from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from avchain.incident.knowledge import package_digest
from avchain.incident.models import (
    AnalysisRecord,
    ExecutionReceipt,
    Incident,
    RemediationPackage,
)
from avchain.incident.triage import validate_triage
from avchain.utils.helpers import canonical_json_bytes, compute_sha256


def bindings_digest(analysis: AnalysisRecord) -> str:
    return compute_sha256(
        canonical_json_bytes(
            {"actions": [a.model_dump() for a in analysis.output.actions]}
        )
    )


@dataclass(frozen=True)
class LocalApproval:
    """An explicit host-side capability. Never parsed from model output."""

    incident_id: str
    package_digest: str
    bindings_digest: str
    root_hash: str
    expires_at: datetime


class ScopedExecutor:
    """Reversible file operations within an operator-approved, quiescent root.

    This is a local POC, not an OS sandbox or protection against a process that
    concurrently rewrites parent directories. No shell/process/network actions.
    A durable local journal precedes every mutation; rollback refuses to clobber
    any file changed by another actor after this executor's write.
    """

    def __init__(self, root: Path, state_dir: Path):
        if root.is_symlink() or state_dir.is_symlink():
            raise ValueError("Symlink scopes are forbidden")
        self.root = root.resolve(strict=True)
        self.state_dir = state_dir.resolve()
        if self.state_dir == self.root or self.state_dir.is_relative_to(self.root):
            raise ValueError("Recovery state must be outside investigated root")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.last_run_id: str | None = None

    def _safe_path(self, relative: str, *, missing: bool = False) -> Path:
        rel = Path(relative)
        if rel.is_absolute() or ".." in rel.parts or not rel.parts:
            raise ValueError("Path escapes approved root")
        path = self.root / rel
        for ancestor in [path, *path.parents]:
            if ancestor == self.root:
                break
            if ancestor.is_symlink():
                raise ValueError("Symlink in artifact path")
        if not path.resolve().is_relative_to(self.root):
            raise ValueError("Path escapes approved root")
        if (path.exists() or not missing) and (
            not path.is_file() or path.stat().st_nlink != 1
        ):
            raise ValueError("Only unlinked regular files are supported")
        return path

    def apply(
        self,
        incident: Incident,
        package: RemediationPackage,
        analysis: AnalysisRecord,
        paths: dict[str, Path],
        approval: LocalApproval,
    ) -> ExecutionReceipt:
        validate_triage(analysis.output, incident, package)
        digest = package_digest(package)
        now = datetime.now(UTC)
        if (
            approval.incident_id != incident.incident_id
            or approval.package_digest != digest
            or approval.bindings_digest != bindings_digest(analysis)
            or approval.root_hash != compute_sha256(str(self.root).encode())
            or approval.expires_at.tzinfo is None
            or approval.expires_at <= now
            or not package.issued_at <= now < package.expires_at
        ):
            raise ValueError("Missing, stale or mismatched local execution approval")
        if not analysis.output.actions:
            return ExecutionReceipt(
                status="blocked",
                incident_id=incident.incident_id,
                package_digest=digest,
                operations=[],
                explanation="No authorized actions",
            )
        facts = {a.artifact_id: a for a in incident.artifacts}
        templates = {a.action_id: a for a in package.actions}
        prepared: list[dict[str, str]] = []
        used: set[Path] = set()
        for binding in analysis.output.actions:
            source = paths.get(binding.artifact_id)
            if source is None:
                raise ValueError("Unknown local artifact")
            path = self._safe_path(str(source.relative_to(self.root)))
            if path in used:
                raise ValueError("Multiple mutations of one artifact are forbidden")
            used.add(path)
            fact = facts[binding.artifact_id]
            raw = path.read_bytes()
            if compute_sha256(raw) != fact.digest:
                raise ValueError("Artifact changed since investigation")
            operation = templates[binding.action_id].operation
            updated = b""
            if operation == "disable_npm_hook":
                document = json.loads(raw)
                scripts = document.get("scripts", {})
                if path.name != "package.json" or fact.hook not in scripts:
                    raise ValueError("Hook precondition failed")
                del scripts[fact.hook]
                updated = (json.dumps(document, indent=2) + "\n").encode()
            prepared.append(
                {
                    "artifact_id": binding.artifact_id,
                    "relative": str(path.relative_to(self.root)),
                    "before": fact.digest,
                    "operation": operation,
                    "after": compute_sha256(updated) if updated else "absent",
                    "mode": oct(stat.S_IMODE(path.stat().st_mode)),
                    "backup": f"{len(prepared)}.original",
                    "staged": f"{len(prepared)}.updated",
                }
            )
        run_id = uuid4().hex
        self.last_run_id = run_id
        run_dir = self.state_dir / run_id
        run_dir.mkdir(mode=0o700)
        # Persist originals and proposed outputs before any mutation.
        for row in prepared:
            path = self._safe_path(row["relative"])
            original = path.read_bytes()
            if compute_sha256(original) != row["before"]:
                raise ValueError("Artifact changed during preparation")
            self._persist_bytes(run_dir / row["backup"], original)
            if row["operation"] == "disable_npm_hook":
                doc = json.loads(original)
                del doc["scripts"][facts[row["artifact_id"]].hook]
                self._persist_bytes(
                    run_dir / row["staged"],
                    (json.dumps(doc, indent=2) + "\n").encode(),
                    mode=int(row["mode"], 8),
                )
        journal: dict[str, Any] = {
            "root_hash": approval.root_hash,
            "incident_id": incident.incident_id,
            "package_digest": digest,
            "operations": prepared,
            "status": "prepared",
        }
        self._write_journal(run_dir, journal)
        try:
            for row in prepared:
                path = self._safe_path(row["relative"])
                if compute_sha256(path.read_bytes()) != row["before"]:
                    raise ValueError("Artifact changed immediately before write")
                if row["operation"] == "quarantine_file":
                    os.replace(path, run_dir / (row["backup"] + ".quarantined"))
                else:
                    os.replace(run_dir / row["staged"], path)
            self._postcheck(prepared)
            journal["status"] = "applied"
            self._write_journal(run_dir, journal)
        except (OSError, ValueError):
            return self.restore(run_id)
        return self._receipt(
            journal, "applied", "Exact approved actions passed postchecks"
        )

    def _postcheck(self, rows: list[dict[str, str]]) -> None:
        for row in rows:
            path = self._safe_path(row["relative"], missing=True)
            if row["after"] == "absent":
                if path.exists():
                    raise ValueError("Quarantine did not remove original")
            elif (
                not path.is_file() or compute_sha256(path.read_bytes()) != row["after"]
            ):
                raise ValueError("Postcheck mismatch")

    def restore(self, run_id: str) -> ExecutionReceipt:
        if len(run_id) != 32 or any(c not in "0123456789abcdef" for c in run_id):
            raise ValueError("Invalid recovery run identifier")
        run_dir = self.state_dir / run_id
        if run_dir.is_symlink():
            raise ValueError("Symlink recovery directory")
        journal = json.loads((run_dir / "journal.json").read_text())
        if journal["root_hash"] != compute_sha256(str(self.root).encode()):
            raise ValueError("Recovery scope mismatch")
        failures = False
        for row in reversed(journal["operations"]):
            try:
                path = self._safe_path(row["relative"], missing=True)
                backup = run_dir / row["backup"]
                if (
                    backup.parent != run_dir
                    or backup.is_symlink()
                    or not backup.is_file()
                    or backup.stat().st_nlink != 1
                ):
                    raise ValueError("Invalid backup path")
                original = backup.read_bytes()
                if compute_sha256(original) != row["before"]:
                    raise ValueError("Recovery evidence corrupted")
                current = (
                    compute_sha256(path.read_bytes()) if path.exists() else "absent"
                )
                if current == row["before"]:
                    continue
                if current != row["after"]:
                    raise ValueError(
                        "Recovery refuses to overwrite a concurrent change"
                    )
                temp = run_dir / f"restore-{uuid4().hex}.tmp"
                self._persist_bytes(temp, original, mode=int(row["mode"], 8))
                os.replace(temp, path)
                if compute_sha256(path.read_bytes()) != row["before"]:
                    raise ValueError("Recovery verification failed")
            except (OSError, ValueError):
                failures = True
        status = "rollback_incomplete" if failures else "rolled_back"
        journal["status"] = status
        self._write_journal(run_dir, journal)
        return self._receipt(
            journal,
            status,
            "Recovery refused conflicts" if failures else "Original bytes restored",
        )

    @staticmethod
    def _persist_bytes(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            os.chmod(path, mode)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())

    @staticmethod
    def _write_journal(run_dir: Path, journal: dict[str, Any]) -> None:
        temp = run_dir / "journal.tmp"
        with temp.open("w") as stream:
            stream.write(json.dumps(journal, sort_keys=True))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, run_dir / "journal.json")

    @staticmethod
    def _receipt(
        journal: dict[str, Any], status: str, explanation: str
    ) -> ExecutionReceipt:
        # Local recovery journals contain paths. Shared receipts do not.
        return ExecutionReceipt.model_validate(
            {
                "status": status,
                "incident_id": journal["incident_id"],
                "package_digest": journal["package_digest"],
                "operations": [
                    {
                        k: v
                        for k, v in row.items()
                        if k in {"artifact_id", "operation", "before", "after"}
                    }
                    for row in journal["operations"]
                ],
                "explanation": explanation,
            }
        )
