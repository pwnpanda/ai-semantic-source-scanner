"""Tests for ai_codescan.cli."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ai_codescan.cli import app

runner = CliRunner()


def test_help_shows_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "prep" in result.stdout
    assert "cache" in result.stdout
    assert "status" in result.stdout


def test_prep_help_shows_flags() -> None:
    result = runner.invoke(app, ["prep", "--help"])
    assert result.exit_code == 0
    assert "--cache-dir" in result.stdout
    assert "--commit" in result.stdout


def test_cache_list_handles_missing_root(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--cache-dir", str(tmp_path / "nope"), "cache", "list"])
    assert result.exit_code == 0
    assert "No cached repos" in result.stdout


def test_status_with_no_run_says_no_runs(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--cache-dir", str(tmp_path), "status"],
    )
    assert result.exit_code == 0
    assert "No cached repos" in result.stdout


@pytest.mark.integration
def test_prep_creates_snapshot_and_repo_md(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-react")],
    )
    assert result.exit_code == 0, result.stdout
    repo_dirs = list(cache.iterdir())
    assert len(repo_dirs) == 1
    repo_dir = repo_dirs[0]
    assert (repo_dir / "source" / "package.json").is_file()
    assert (repo_dir / "manifest.jsonl").is_file()
    repo_md = (repo_dir / "repo.md").read_text(encoding="utf-8")
    assert "react" in repo_md
    assert "typescript" in repo_md


@pytest.mark.integration
def test_prep_idempotent_on_second_run(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    args = ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)
    assert first.exit_code == 0
    assert second.exit_code == 0
    assert "skipped" in second.stdout.lower()
