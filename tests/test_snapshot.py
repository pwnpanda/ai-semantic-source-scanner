"""Tests for ai_codescan.snapshot."""

import subprocess
from pathlib import Path

import pytest

from ai_codescan.snapshot import SnapshotResult, take_snapshot


def _init_git_repo(repo: Path) -> str:
    """Create a one-commit git repo at ``repo`` and return the commit SHA."""
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test"],
        check=True,
    )
    (repo / "hello.txt").write_text("hi")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "init"],
        check=True,
    )
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.mark.integration
def test_snapshot_uses_git_worktree_when_target_is_git(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    sha = _init_git_repo(target)
    cache = tmp_path / "cache"

    result = take_snapshot(target, cache_dir=cache)

    assert isinstance(result, SnapshotResult)
    assert result.snapshot_dir == cache / "source"
    assert (result.snapshot_dir / "hello.txt").is_file()
    assert (result.snapshot_dir / "hello.txt").read_text() == "hi"
    assert result.commit_sha == sha
    assert result.method == "git-worktree"
    assert (cache / "manifest.jsonl").is_file()


@pytest.mark.integration
def test_snapshot_pinned_to_explicit_commit(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    first_sha = _init_git_repo(target)
    (target / "hello.txt").write_text("changed")
    subprocess.run(["git", "-C", str(target), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(target), "commit", "-q", "-m", "second"],
        check=True,
    )
    cache = tmp_path / "cache"

    result = take_snapshot(target, cache_dir=cache, commit=first_sha)

    assert result.commit_sha == first_sha
    assert (result.snapshot_dir / "hello.txt").read_text() == "hi"


@pytest.mark.integration
def test_snapshot_idempotent_when_manifest_matches(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    _init_git_repo(target)
    cache = tmp_path / "cache"

    first = take_snapshot(target, cache_dir=cache)
    second = take_snapshot(target, cache_dir=cache)

    assert first.commit_sha == second.commit_sha
    assert second.skipped is True
    assert first.skipped is False


@pytest.mark.integration
def test_snapshot_cp_for_non_git_target(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.js").write_text("module.exports = 1;")
    (target / "sub").mkdir()
    (target / "sub" / "b.html").write_text("<p>hi</p>")
    cache = tmp_path / "cache"

    result = take_snapshot(target, cache_dir=cache)

    assert result.method == "cp"
    assert result.commit_sha is None
    assert (result.snapshot_dir / "a.js").read_text() == "module.exports = 1;"
    assert (result.snapshot_dir / "sub" / "b.html").read_text() == "<p>hi</p>"


@pytest.mark.integration
def test_snapshot_marks_files_read_only(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.js").write_text("x")
    cache = tmp_path / "cache"

    result = take_snapshot(target, cache_dir=cache)

    snap_file = result.snapshot_dir / "a.js"
    assert not (snap_file.stat().st_mode & 0o222)


@pytest.mark.integration
def test_snapshot_cp_idempotent_when_manifest_matches(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.js").write_text("x")
    cache = tmp_path / "cache"

    first = take_snapshot(target, cache_dir=cache)
    second = take_snapshot(target, cache_dir=cache)

    assert first.skipped is False
    assert second.skipped is True
