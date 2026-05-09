"""Tests for ai_codescan.config."""

import subprocess
from pathlib import Path

from ai_codescan.config import compute_repo_id, default_cache_root, repo_cache_dir


def test_repo_id_uses_basename_and_path_hash(tmp_path: Path) -> None:
    repo = tmp_path / "my-target"
    repo.mkdir()
    repo_id = compute_repo_id(repo)
    assert repo_id.startswith("my-target-")
    assert len(repo_id) == len("my-target-") + 8


def test_repo_id_is_stable_across_calls(tmp_path: Path) -> None:
    repo = tmp_path / "stable"
    repo.mkdir()
    assert compute_repo_id(repo) == compute_repo_id(repo)


def test_repo_id_differs_for_different_paths(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert compute_repo_id(a) != compute_repo_id(b)


def test_default_cache_root_is_home_subdir() -> None:
    root = default_cache_root()
    assert root == Path.home() / ".ai_codescan" / "repos"


def test_repo_cache_dir_combines_root_and_id(tmp_path: Path) -> None:
    repo = tmp_path / "x"
    repo.mkdir()
    cache_dir = repo_cache_dir(repo, cache_root=tmp_path / "cache")
    assert cache_dir.parent == tmp_path / "cache"
    assert cache_dir.name == compute_repo_id(repo)


def test_repo_id_uses_git_remote_when_present(tmp_path: Path) -> None:
    """When the target is a git repo with origin set, the hash derives from the remote URL."""
    repo = tmp_path / "with-remote"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "remote", "add", "origin", "https://example.test/foo/bar.git"],
        check=True,
    )

    repo_id_with_remote = compute_repo_id(repo)

    # Removing the origin remote should produce a different id, derived from the path instead.
    subprocess.run(
        ["git", "-C", str(repo), "remote", "remove", "origin"],
        check=True,
    )
    repo_id_no_remote = compute_repo_id(repo)

    assert repo_id_with_remote != repo_id_no_remote
    assert repo_id_with_remote.startswith("with-remote-")
    assert repo_id_no_remote.startswith("with-remote-")


def test_repo_id_with_git_dir_but_no_origin_falls_back(tmp_path: Path) -> None:
    """A git repo without an origin remote still produces a stable id via the abs path."""
    repo = tmp_path / "no-origin"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    # No remote configured.
    a = compute_repo_id(repo)
    b = compute_repo_id(repo)
    assert a == b
    assert a.startswith("no-origin-")
