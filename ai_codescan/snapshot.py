"""Repository snapshot management.

Takes a deterministic, read-only snapshot of a target repo into the cache dir.
Uses ``git worktree`` for clean or explicitly pinned Git targets (cheap,
shares objects); copies dirty unpinned and non-Git targets.
"""

from __future__ import annotations

import shutil
import stat
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ai_codescan.manifest import IGNORED_SOURCE_DIRS, build_manifest, read_manifest, write_manifest


@dataclass(frozen=True, slots=True)
class SnapshotResult:
    """What :func:`take_snapshot` produces."""

    snapshot_dir: Path
    manifest_path: Path
    commit_sha: str | None
    method: Literal["git-worktree", "cp"]
    skipped: bool  # True when a previous matching snapshot was reused
    index_reused: bool = False  # Set by prep when source-derived rows were reused


def _is_git_repo(target: Path) -> bool:
    return (target / ".git").exists()


def git_worktree_is_dirty(target: Path) -> bool:
    """Return whether tracked or untracked Git source differs from ``HEAD``."""
    result = subprocess.run(  # noqa: S603 - argv-only, no shell
        [  # noqa: S607
            "git",
            "-C",
            str(target),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode != 0 or bool(result.stdout.strip())


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
    try:
        recorded_commit = head_marker.read_text(encoding="utf-8").strip()
    except OSError:
        return False
    return recorded_commit == expected_commit and _cached_snapshot_matches_manifest(cache_dir)


def force_remove(_func, path, _exc) -> None:
    """``shutil.rmtree`` ``onexc`` hook to clear read-only bits before retry.

    Snapshots are taken read-only, so removing one trips two things the naive
    hook got wrong: deleting an entry needs write+execute on its *parent*, not
    just on the entry itself, and a directory has to go via ``rmdir`` —
    ``unlink`` raises ``IsADirectoryError``. Getting either wrong made
    ``cache rm`` fail outright on any snapshot tree.
    """
    target = Path(path)
    for node in (target.parent, target):
        with suppress(OSError):
            node.chmod(node.stat().st_mode | stat.S_IRWXU)
    if target.is_dir() and not target.is_symlink():
        with suppress(FileNotFoundError):
            target.rmdir()
        return
    target.unlink(missing_ok=True)


def _cp_snapshot(target: Path, cache_dir: Path) -> Path:
    snapshot_dir = cache_dir / "source"
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir, onexc=force_remove)
    shutil.copytree(target, snapshot_dir, symlinks=True, ignore=_ignored_snapshot_entries)
    return snapshot_dir


def _ignored_snapshot_entries(directory: str, entries: list[str]) -> list[str]:
    """Exclude dependency/build trees and links from copy-based snapshots."""
    root = Path(directory)
    return [
        entry for entry in entries if entry in IGNORED_SOURCE_DIRS or (root / entry).is_symlink()
    ]


def _cached_snapshot_matches_manifest(cache_dir: Path) -> bool:
    """Return whether cached source content matches its durable manifest."""
    manifest_path = cache_dir / "manifest.jsonl"
    snapshot_dir = cache_dir / "source"
    if (
        not manifest_path.is_file()
        or manifest_path.is_symlink()
        or not snapshot_dir.is_dir()
        or snapshot_dir.is_symlink()
    ):
        return False
    try:
        return read_manifest(manifest_path) == build_manifest(snapshot_dir)
    except (OSError, TypeError, ValueError):
        return False


def _manifest_already_matches(cache_dir: Path, source_root: Path) -> bool:
    """For copied targets, require matching live and cached source content."""
    if not _cached_snapshot_matches_manifest(cache_dir) or not source_root.is_dir():
        return False
    try:
        return read_manifest(cache_dir / "manifest.jsonl") == build_manifest(source_root)
    except (OSError, TypeError, ValueError):
        return False


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
            shutil.rmtree(snapshot_dir, onexc=force_remove)
    # Prune any stale worktree registrations in the source repo. Users who
    # manually delete the cache (or whose previous run was killed) leave
    # entries in `<target>/.git/worktrees/<name>/` that block `worktree add`
    # with "missing but already registered worktree". Pruning is idempotent.
    subprocess.run(  # noqa: S603 - argv-only, no shell
        ["git", "-C", str(target), "worktree", "prune"],  # noqa: S607
        capture_output=True,
        check=False,
    )
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

    Uses ``git worktree`` for clean or explicitly pinned Git source. Dirty,
    unpinned Git source uses a copy so the snapshot matches the files the user
    asked to scan. A re-invocation with matching state returns ``skipped=True``.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    snapshot_dir = cache_dir / "source"
    manifest_path = cache_dir / "manifest.jsonl"

    is_git_repo = _is_git_repo(target)
    use_git_worktree = is_git_repo and (bool(commit) or not git_worktree_is_dirty(target))
    if use_git_worktree:
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
        if _manifest_already_matches(cache_dir, target):
            return SnapshotResult(
                snapshot_dir=snapshot_dir,
                manifest_path=manifest_path,
                commit_sha=None,
                method="cp",
                skipped=True,
            )
        if is_git_repo and snapshot_dir.exists():
            subprocess.run(  # noqa: S603 - argv-only, no shell
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
        snapshot_dir = _cp_snapshot(target, cache_dir)
        (cache_dir / ".snapshot-commit").unlink(missing_ok=True)
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
