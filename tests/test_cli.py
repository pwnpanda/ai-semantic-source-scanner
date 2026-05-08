"""Tests for ai_codescan.cli."""

from pathlib import Path

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
