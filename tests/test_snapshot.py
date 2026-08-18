"""Tests for ai_codescan.snapshot."""

import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from ai_codescan.snapshot import SnapshotResult, force_remove, take_snapshot


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
    (target / "hello.txt").write_text("dirty", encoding="utf-8")
    cache = tmp_path / "cache"

    result = take_snapshot(target, cache_dir=cache, commit=first_sha)

    assert result.commit_sha == first_sha
    assert (result.snapshot_dir / "hello.txt").read_text() == "hi"


@pytest.mark.integration
def test_snapshot_dirty_git_uses_live_copy(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    _init_git_repo(target)
    changed = target / "hello.txt"
    changed.write_text("dirty", encoding="utf-8")
    untracked = target / "New.kt"
    untracked.write_text("fun live() = true\n", encoding="utf-8")
    cache = tmp_path / "cache"

    first = take_snapshot(target, cache_dir=cache)
    second = take_snapshot(target, cache_dir=cache)

    assert first.method == "cp"
    assert first.commit_sha is None
    assert (first.snapshot_dir / "hello.txt").read_text(encoding="utf-8") == "dirty"
    assert (first.snapshot_dir / "New.kt").is_file()
    assert second.skipped is True


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
def test_snapshot_cp_excludes_local_dependencies_and_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "app.js").write_text("export const live = true;\n", encoding="utf-8")
    dependency = target / "node_modules" / "package"
    dependency.mkdir(parents=True)
    (dependency / "index.js").write_text("export const vendored = true;\n", encoding="utf-8")
    external = tmp_path / "external.yml"
    external.write_text("password: external-secret\n", encoding="utf-8")
    (target / "linked.yml").symlink_to(external)

    result = take_snapshot(target, cache_dir=tmp_path / "cache")

    assert (result.snapshot_dir / "app.js").is_file()
    assert not (result.snapshot_dir / "node_modules").exists()
    assert not (result.snapshot_dir / "linked.yml").exists()


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


@pytest.mark.integration
def test_snapshot_cp_refreshes_when_target_changes(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    stale = target / "stale.yml"
    stale.write_text("on: push\n", encoding="utf-8")
    cache = tmp_path / "cache"

    first = take_snapshot(target, cache_dir=cache)
    stale.unlink()
    (target / "current.yml").write_text("on: pull_request\n", encoding="utf-8")
    second = take_snapshot(target, cache_dir=cache)

    assert first.skipped is False
    assert second.skipped is False
    assert not (second.snapshot_dir / "stale.yml").exists()
    assert (second.snapshot_dir / "current.yml").is_file()


@pytest.mark.integration
@pytest.mark.parametrize("git_target", [False, True])
@pytest.mark.parametrize("damage", ["deleted", "corrupt"])
def test_snapshot_does_not_reuse_damaged_cached_source(
    tmp_path: Path,
    git_target: bool,
    damage: str,
) -> None:
    target = tmp_path / "src"
    target.mkdir()
    if git_target:
        _init_git_repo(target)
    else:
        (target / "hello.txt").write_text("hi", encoding="utf-8")
    cache = tmp_path / "cache"
    first = take_snapshot(target, cache_dir=cache)

    if damage == "deleted":
        shutil.rmtree(first.snapshot_dir, onexc=force_remove)
    else:
        cached_file = first.snapshot_dir / "hello.txt"
        cached_file.chmod(cached_file.stat().st_mode | stat.S_IWUSR)
        cached_file.write_text("corrupt", encoding="utf-8")

    second = take_snapshot(target, cache_dir=cache)

    assert second.skipped is False
    assert (second.snapshot_dir / "hello.txt").read_text(encoding="utf-8") == "hi"


def test_force_remove_clears_a_read_only_snapshot_tree(tmp_path: Path) -> None:
    """``cache rm`` must delete a snapshot, which is deliberately read-only.

    The previous hook always called ``unlink``, which raises
    ``IsADirectoryError`` on a directory, and never granted write on the
    *parent* — so removal failed outright on any real snapshot.
    """
    root = tmp_path / "cached-repo"
    nested = root / "source" / "storage" / "deep"
    nested.mkdir(parents=True)
    (nested / "file.txt").write_text("data", encoding="utf-8")
    (root / "source" / "top.txt").write_text("data", encoding="utf-8")

    # Mirror take_snapshot: strip write bits from every entry, deepest first.
    for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        path.chmod(path.stat().st_mode & ~stat.S_IWUSR)
    root.chmod(root.stat().st_mode & ~stat.S_IWUSR)

    shutil.rmtree(root, onexc=force_remove)

    assert not root.exists()
