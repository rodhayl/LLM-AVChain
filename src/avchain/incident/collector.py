from __future__ import annotations

import json
import shlex
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from avchain.incident.models import Artifact, Incident
from avchain.utils.helpers import compute_sha256


class IncidentCollector:
    """Read an explicitly supplied directory without executing its contents.

    Local paths remain in this object. Shared evidence uses hashed identifiers.
    The hook/canary features are one safe demonstration adapter, not a universal
    maliciousness predicate. Arbitrary files still enter the investigation.
    """

    def __init__(self, root: Path, *, max_files: int = 128, max_bytes: int = 65536):
        if root.is_symlink():
            raise ValueError("Symlink root is not permitted")
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("Investigation root must be a directory")
        self.max_files = max_files
        self.max_bytes = max_bytes
        self.paths: dict[str, Path] = {}

    def collect(self) -> Incident:
        self.paths = {}
        artifacts: list[Artifact] = []
        limitations: list[str] = []
        paths: list[Path] = []
        # Path.walk does not follow directory symlinks. Bound traversal too.
        inspected = 0
        for directory_count, (directory, dirs, filenames) in enumerate(
            self.root.walk(follow_symlinks=False)
        ):
            if directory_count >= self.max_files:
                limitations.append("directory_limit_reached")
                break
            dirs[:] = sorted(d for d in dirs if not (directory / d).is_symlink())
            for filename in sorted(filenames):
                inspected += 1
                if inspected > self.max_files:
                    limitations.append("file_limit_reached")
                    break
                path = directory / filename
                if path.is_symlink() or not path.is_file():
                    limitations.append("non_regular_file_skipped")
                    continue
                if path.stat().st_size > self.max_bytes:
                    limitations.append("oversized_file_skipped")
                    continue
                paths.append(path)
            if inspected > self.max_files:
                break
        path_ids = {
            p: compute_sha256(str(p.relative_to(self.root)).encode()) for p in paths
        }
        target_ids: set[str] = set()
        hooks: dict[Path, tuple[str, str]] = {}
        for path in paths:
            if path.name != "package.json":
                continue
            try:
                payload = json.loads(path.read_bytes())
                scripts = payload.get("scripts", {})
                for hook in ("preinstall", "install", "postinstall", "prepare"):
                    command = scripts.get(hook)
                    if not isinstance(command, str):
                        continue
                    # Only a direct interpreter + local filename is bound.
                    # Shell strings, flags and arbitrary command lines stay data.
                    words = shlex.split(command)
                    if len(words) != 2 or words[0] not in {"node", "python", "python3"}:
                        continue
                    target = path.parent / words[1]
                    if ".." in Path(words[1]).parts or Path(words[1]).is_absolute():
                        continue
                    if target in path_ids:
                        target_ids.add(path_ids[target])
                        if path in hooks:
                            limitations.append("multiple_hooks_require_manual_review")
                            hooks.pop(path)
                            break
                        hooks[path] = (hook, path_ids[target])
            except (ValueError, AttributeError, UnicodeError):
                limitations.append("invalid_manifest")
        for path in paths:
            raw = path.read_bytes()
            text = raw.decode("utf-8", errors="replace")
            artifact_id = path_ids[path]
            tags = ["file"]
            if artifact_id in target_ids:
                tags.append("install_hook_target")
            if "AVCHAIN_CANARY" in text and (
                "readFileSync" in text or "read_text" in text
            ):
                tags.append("canary_read")
            if "127.0.0.1" in text and any(
                t in text for t in ("request", "fetch", "urlopen")
            ):
                tags.append("loopback_egress")
            selected_hook, related = hooks.get(path, (None, None))
            if selected_hook:
                tags.append("install_hook_manifest")
            artifacts.append(
                Artifact(
                    artifact_id=artifact_id,
                    path_hash=compute_sha256(str(path).encode()),
                    digest=compute_sha256(raw),
                    excerpt=text[:8192],
                    tags=tags,
                    hook=selected_hook,
                    related_artifact_id=related,
                )
            )
            self.paths[artifact_id] = path
        return Incident(
            incident_id=str(uuid4()),
            observed_at=datetime.now(UTC),
            artifacts=artifacts,
            limitations=sorted(set(limitations)),
        )
