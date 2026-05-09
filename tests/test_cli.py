"""Tests for ai_codescan.cli."""

import json
from pathlib import Path

import duckdb
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


@pytest.mark.integration
def test_cache_list_shows_repo_after_prep(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    result = runner.invoke(app, ["--cache-dir", str(cache), "cache", "list"])
    assert result.exit_code == 0
    assert "tiny-express-" in result.stdout
    assert "MiB" in result.stdout or "KiB" in result.stdout or "B " in result.stdout


@pytest.mark.integration
def test_cache_rm_removes_repo_dir(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    result = runner.invoke(app, ["--cache-dir", str(cache), "cache", "rm", repo_id])
    assert result.exit_code == 0
    assert not (cache / repo_id).exists()


@pytest.mark.integration
def test_prep_populates_duckdb(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-react")],
    )
    repo_dirs = list(cache.iterdir())
    db_path = repo_dirs[0] / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    files_row = conn.execute("SELECT COUNT(*) FROM files").fetchone()
    symbols_row = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()
    assert files_row is not None
    assert symbols_row is not None
    assert files_row[0] >= 1
    assert symbols_row[0] >= 1


@pytest.mark.integration
def test_query_subcommand_returns_rows(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "query",
            "--repo-id",
            repo_id,
            "SELECT COUNT(*) AS n FROM symbols",
        ],
    )
    assert result.exit_code == 0
    assert "n" in result.stdout


@pytest.mark.integration
def test_flows_subcommand_handles_empty_db(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "flows", "--repo-id", repo_id, "--from", "anything"],
    )
    assert result.exit_code == 0
    assert "no flows" in result.stdout.lower() or result.stdout.strip() == ""


def test_list_bug_classes_prints_entries() -> None:
    result = runner.invoke(app, ["list-bug-classes"])
    assert result.exit_code == 0
    assert "xss" in result.stdout
    assert "sqli" in result.stdout


@pytest.mark.integration
def test_prep_emits_entrypoints_md(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    ep = (cache / repo_id / "entrypoints.md").read_text()
    assert "Entrypoints:" in ep


@pytest.mark.integration
def test_view_command_renders_for_known_file(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    snap_root = cache / repo_id / "source"
    server_js = next(snap_root.rglob("server.js"))
    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "view", "--file", str(server_js), "--repo-id", repo_id],
    )
    assert result.exit_code == 0
    assert "View:" in result.stdout


def test_unknown_bug_class_errors_with_suggestion(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "prep",
            str(fixtures_dir / "tiny-express"),
            "--target-bug-class",
            "xs",
        ],
    )
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "did you mean" in combined.lower()


@pytest.mark.integration
def test_nominate_creates_nominations_md(
    tmp_path: Path, fixtures_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    monkeypatch.setenv("PATH", "/nonexistent")
    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "nominate", "--repo-id", repo_id],
    )
    assert result.exit_code == 0
    runs = sorted((cache / repo_id / "runs").iterdir())
    assert runs
    nominations_path = runs[-1] / "nominations.md"
    assert nominations_path.is_file()
    body = nominations_path.read_text()
    assert "Stream A" in body and "Stream B" in body and "Stream C" in body


@pytest.mark.integration
def test_gate_1_yes_marks_all(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    runs_root = cache / repo_id / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    run_dir = runs_root / "deadbeef"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "nominations.md").write_text(
        (fixtures_dir / "nominations-sample.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "gate-1", "--repo-id", repo_id, "--yes"],
    )
    assert result.exit_code == 0
    txt = (run_dir / "nominations.md").read_text()
    assert "y/n: y" in txt and "y/n: n" in txt


def test_install_skills_command_runs() -> None:
    """install-skills copies into ~/.claude/skills/ — just verify exit 0."""
    result = runner.invoke(app, ["install-skills"])
    assert result.exit_code == 0
    assert "installed skill" in result.stdout


def test_nominate_help_advertises_llm_flags() -> None:
    result = runner.invoke(app, ["nominate", "--help"])
    assert result.exit_code == 0
    assert "--llm-provider" in result.stdout
    assert "--llm-model" in result.stdout


def test_run_help_advertises_llm_flags() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "--llm-provider" in result.stdout
    assert "--llm-model" in result.stdout


def test_nominate_rejects_unknown_provider(
    tmp_path: Path, fixtures_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    monkeypatch.setenv("PATH", "/nonexistent")
    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "nominate",
            "--repo-id",
            repo_id,
            "--llm-provider",
            "not-a-thing",
        ],
    )
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "unknown provider" in combined.lower()


@pytest.mark.integration
def test_nominate_persists_llm_config_to_run_json(
    tmp_path: Path, fixtures_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    monkeypatch.setenv("PATH", "/nonexistent")
    runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "nominate",
            "--repo-id",
            repo_id,
            "--llm-provider",
            "gemini",
            "--llm-model",
            "gemini-2.5-pro",
        ],
    )
    runs = sorted((cache / repo_id / "runs").iterdir())
    run_json = json.loads((runs[-1] / "run.json").read_text(encoding="utf-8"))
    assert run_json["llm_provider"] == "gemini"
    assert run_json["llm_model"] == "gemini-2.5-pro"


def test_analyze_help_advertises_llm_flags() -> None:
    result = runner.invoke(app, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "--llm-provider" in result.stdout
    assert "--llm-model" in result.stdout


def test_gate_2_help_advertises_yes() -> None:
    result = runner.invoke(app, ["gate-2", "--help"])
    assert result.exit_code == 0
    assert "--yes" in result.stdout


def test_gate_2_yes_short_circuits(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    runs_root = cache / repo_id / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    run_dir = runs_root / "rrr"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "findings").mkdir()

    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "gate-2", "--repo-id", repo_id, "--yes"],
    )
    assert result.exit_code == 0
    assert "keeping all findings" in result.stdout


def test_validate_help_advertises_no_sandbox() -> None:
    result = runner.invoke(app, ["validate", "--help"])
    assert result.exit_code == 0
    assert "--no-sandbox" in result.stdout
    assert "--llm-provider" in result.stdout


def test_gate_3_help_advertises_yes() -> None:
    result = runner.invoke(app, ["gate-3", "--help"])
    assert result.exit_code == 0
    assert "--yes" in result.stdout
