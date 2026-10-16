"""Packaging must not archive generated reports, caches, keys or test workspaces."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


def _build_sdist(root: Path) -> tuple[bytes, dict[str, bytes]]:
    result = subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", "sdist"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    archive = next((root / "dist").glob("*.tar.gz"))
    with tarfile.open(archive) as stream:
        files = {
            member.name.split("/", 1)[1]: stream.extractfile(member).read()
            for member in stream.getmembers()
            if member.isfile()
        }
    return hashlib.sha256(archive.read_bytes()).digest(), files


@pytest.mark.parametrize("nested_vcs_root", [False, True])
def test_sdist_is_unchanged_by_generated_workspace_data(
    tmp_path: Path, nested_vcs_root: bool
) -> None:
    # Both builds have identical source bytes and differ only in generated files.
    if nested_vcs_root:
        (tmp_path / ".git").mkdir()
        (tmp_path / ".gitignore").write_text(
            "/src/avchain/coverage/\n", encoding="utf-8"
        )
    root = tmp_path / "package"
    root.mkdir()
    # Hatchling stops ancestor ignore discovery at a .git boundary. This fixture
    # is a standalone package, not a member of the checkout containing tmp_path.
    (root / ".git").mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copyfile(name, root / name)
    shutil.copytree("src", root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    clean_digest, clean_files = _build_sdist(root)
    for name in (
        "reports/verification/temp/pytest/nested/secret.txt",
        "reports/verification/temp/sdist-copy/src/avchain/fake.py",
        "src/avchain/__pycache__/fake.pyc",
        ".venv/site-packages/example.py",
        "runtime/keys/private.pem",
        "data/ledger.db",
        ".env",
        ".pytest_cache/state",
        "build/stale.py",
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("generated data must never ship", encoding="utf-8")
    dirty_digest, dirty_files = _build_sdist(root)
    assert clean_files == dirty_files
    assert clean_digest == dirty_digest
    assert "src/avchain/coverage/central.py" in dirty_files
    assert "pyproject.toml" in dirty_files
    assert "LICENSE" in dirty_files
    assert all(
        name.startswith("src/avchain/")
        or name in {"pyproject.toml", "README.md", "LICENSE", "PKG-INFO"}
        for name in dirty_files
    )
