"""Repository snapshot management.

Takes a deterministic, read-only snapshot of a target repo into the cache dir.
Uses ``git worktree`` when possible (cheap, shares objects); falls back to
``cp -r`` for non-git targets (Task 5).
"""

from __future__ import annotations

import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ai_codescan.manifest import build_manifest, read_manifest, write_manifest


@dataclass(frozen=True, slots=True)
class SnapshotResult:
    """What :func:`take_snapshot` produces."""

    snapshot_dir: Path
    manifest_path: Path
    commit_sha: str | None
    method: Literal["git-worktree", "cp"]
    skipped: bool  # True when a previous matching snapshot was reused


def _is_git_repo(target: Path) -> bool:
    return (target / ".git").exists()


def _resolve_commit(target: Path, commit: str | None) -> str:
    rev = commit or "HEAD"
    # S603/S607: argv list with literal "git" — caller-controlled target/rev are
    # passed as separate args (no shell), and git rev-parse rejects malformed input.
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(target), "rev-parse", rev],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _make_read_only(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode
        path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def _existing_snapshot_matches(
    cache_dir: Path,
    expected_commit: str | None,
) -> bool:
    """Return True if a previous snapshot in ``cache_dir`` is still valid."""
    head_marker = cache_dir / ".snapshot-commit"
    if expected_commit is None or not head_marker.is_file():
        return False
    return head_marker.read_text(encoding="utf-8").strip() == expected_commit


def _force_remove(_func, path, _exc) -> None:
    """``shutil.rmtree`` ``onexc`` hook to clear read-only bits before retry."""
    Path(path).chmod(stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
    Path(path).unlink(missing_ok=True)


def _cp_snapshot(target: Path, cache_dir: Path) -> Path:
    snapshot_dir = cache_dir / "source"
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir, onexc=_force_remove)
    shutil.copytree(target, snapshot_dir, symlinks=False, ignore_dangling_symlinks=True)
    return snapshot_dir


def _manifest_already_matches(cache_dir: Path, snapshot_dir: Path) -> bool:
    """For non-git targets: return True if the snapshot content already matches."""
    manifest_path = cache_dir / "manifest.jsonl"
    if not manifest_path.is_file() or not snapshot_dir.exists():
        return False
    return read_manifest(manifest_path) == build_manifest(snapshot_dir)


def _git_worktree_snapshot(target: Path, cache_dir: Path, commit: str) -> Path:
    snapshot_dir = cache_dir / "source"
    if snapshot_dir.exists():
        # Best-effort: detach the worktree first so git's metadata stays clean.
        # S603/S607: literal argv, no shell.
        subprocess.run(  # noqa: S603
            [  # noqa: S607
                "git",
                "-C",
                str(target),
                "worktree",
                "remove",
                "--force",
                str(snapshot_dir),
            ],
            capture_output=True,
            check=False,
        )
        if snapshot_dir.exists():
            shutil.rmtree(snapshot_dir, onexc=_force_remove)
    cache_dir.mkdir(parents=True, exist_ok=True)
    # S603/S607: literal argv, no shell.
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-C",
            str(target),
            "worktree",
            "add",
            "--detach",
            str(snapshot_dir),
            commit,
        ],
        check=True,
        capture_output=True,
    )
    return snapshot_dir


def take_snapshot(
    target: Path,
    *,
    cache_dir: Path,
    commit: str | None = None,
) -> SnapshotResult:
    """Snapshot ``target`` into ``cache_dir``.

    Uses ``git worktree`` when ``target`` is a git repo, ``cp -r`` otherwise.
    Idempotent: a re-invocation with matching state returns ``skipped=True``.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    snapshot_dir = cache_dir / "source"
    manifest_path = cache_dir / "manifest.jsonl"

    if _is_git_repo(target):
        sha = _resolve_commit(target, commit)
        if _existing_snapshot_matches(cache_dir, sha):
            return SnapshotResult(
                snapshot_dir=snapshot_dir,
                manifest_path=manifest_path,
                commit_sha=sha,
                method="git-worktree",
                skipped=True,
            )
        snapshot_dir = _git_worktree_snapshot(target, cache_dir, sha)
        (cache_dir / ".snapshot-commit").write_text(sha, encoding="utf-8")
        method: Literal["git-worktree", "cp"] = "git-worktree"
        commit_sha: str | None = sha
    else:
        if _manifest_already_matches(cache_dir, snapshot_dir):
            return SnapshotResult(
                snapshot_dir=snapshot_dir,
                manifest_path=manifest_path,
                commit_sha=None,
                method="cp",
                skipped=True,
            )
        snapshot_dir = _cp_snapshot(target, cache_dir)
        method = "cp"
        commit_sha = None

    write_manifest(manifest_path, build_manifest(snapshot_dir))
    _make_read_only(snapshot_dir)
    return SnapshotResult(
        snapshot_dir=snapshot_dir,
        manifest_path=manifest_path,
        commit_sha=commit_sha,
        method=method,
        skipped=False,
    )
