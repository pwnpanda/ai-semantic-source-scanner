"""Tests for ai_codescan.cli."""

import json
import os
import re
from pathlib import Path

import duckdb
import pytest
from typer.testing import CliRunner

from ai_codescan.cli import app

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_WS_RE = re.compile(r"\s+")


def _help_text(stdout: str) -> str:
    """Normalize help output for substring matching.

    Strips ANSI escape codes and collapses runs of whitespace (including
    newlines) to single spaces. Help-text assertions then survive any
    rich-panel wrapping or column-width fluctuation in the test
    environment.
    """
    return _WS_RE.sub(" ", _ANSI_RE.sub("", stdout))


def test_help_shows_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "prep" in result.stdout
    assert "cache" in result.stdout
    assert "status" in result.stdout


def test_prep_help_shows_flags() -> None:
    result = runner.invoke(app, ["prep", "--help"])
    assert result.exit_code == 0
    out = _help_text(result.stdout)
    assert "--cache-dir" in out
    assert "--commit" in out


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
def test_prep_incremental_skip_logs_message(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    args = ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")]
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.stdout
    second = runner.invoke(app, args)
    assert second.exit_code == 0, second.stdout
    out = second.stdout.lower()
    assert "skipping" in out or "incremental" in out


@pytest.mark.integration
def test_prep_force_re_runs_everything(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    args = ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")]
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.stdout
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    db_path = cache / repo_id / "index.duckdb"
    mtime_before = db_path.stat().st_mtime_ns
    # Backdate the existing file so the post-run mtime is unambiguously newer
    # even on filesystems with second-resolution mtime (e.g. ext4 without nsec).
    backdated = mtime_before - 5_000_000_000  # 5s in the past
    os.utime(db_path, ns=(backdated, backdated))
    second = runner.invoke(app, [*args, "--force"])
    assert second.exit_code == 0, second.stdout
    mtime_after = db_path.stat().st_mtime_ns
    assert mtime_after > backdated, (
        f"--force should re-touch index.duckdb (before={backdated} after={mtime_after})"
    )
    out = second.stdout.lower()
    assert "skipping" not in out and "incremental" not in out


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
    combined = result.output or ""
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
    out = _help_text(result.stdout)
    assert "--llm-provider" in out
    assert "--llm-model" in out


def test_run_help_advertises_llm_flags() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    out = _help_text(result.stdout)
    assert "--llm-provider" in out
    assert "--llm-model" in out


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
    combined = result.output or ""
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
    out = _help_text(result.stdout)
    assert "--llm-provider" in out
    assert "--llm-model" in out


def test_gate_2_help_advertises_yes() -> None:
    result = runner.invoke(app, ["gate-2", "--help"])
    assert result.exit_code == 0
    assert "--yes" in _help_text(result.stdout)


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
    out = _help_text(result.stdout)
    assert "--no-sandbox" in out
    assert "--llm-provider" in out


def test_gate_3_help_advertises_yes() -> None:
    result = runner.invoke(app, ["gate-3", "--help"])
    assert result.exit_code == 0
    assert "--yes" in _help_text(result.stdout)


def test_report_help_advertises_flags() -> None:
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
    out = _help_text(result.stdout)
    assert "--report-dir" in out
    assert "--bugbounty" in out


def test_report_writes_for_verified_finding(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    runs_root = cache / repo_id / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    run_dir = runs_root / "rrr"
    findings_dir = run_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "F-001.md").write_text(
        "---\nfinding_id: F-001\nnomination_id: N-001\nflow_id: F1\n"
        "cwe: CWE-89\nstatus: verified\ntitle: SQLi in users.ts:42\n---\n\n"
        "Concrete details about the bug.\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "report",
            "--repo-id",
            repo_id,
            "--report-dir",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.stdout
    files = list(out.glob("*.md"))
    assert files, result.stdout
    assert "critical" in files[0].name
    assert "sqli" in files[0].name


def test_visualize_help_advertises_flags() -> None:
    result = runner.invoke(app, ["visualize", "--help"])
    assert result.exit_code == 0
    out = _help_text(result.stdout)
    assert "--fmt" in out
    assert "--cwe" in out
    assert "--limit" in out


def test_visualize_writes_dot(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    out = tmp_path / "flows.dot"
    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "visualize",
            "--repo-id",
            repo_id,
            "--out",
            str(out),
            "--fmt",
            "dot",
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.is_file()
    assert "digraph" in out.read_text()


def test_serve_help_advertises_flags() -> None:
    result = runner.invoke(app, ["serve", "--help"])
    assert result.exit_code == 0
    out = _help_text(result.stdout)
    assert "--port" in out
    assert "--host" in out
    assert "--open" in out


def test_install_skills_protect_and_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    # Mark wide_nominator as protected.
    result = runner.invoke(app, ["install-skills", "--protect", "wide_nominator"])
    assert result.exit_code == 0
    listing = runner.invoke(app, ["install-skills", "--list-protected"])
    assert "wide_nominator" in listing.stdout
    # Removing the protection works.
    result = runner.invoke(app, ["install-skills", "--unprotect", "wide_nominator"])
    assert result.exit_code == 0
    listing2 = runner.invoke(app, ["install-skills", "--list-protected"])
    assert "no protected skills" in listing2.stdout


def test_install_skills_skips_protected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    # Mark deep_analyzer protected before the first install.
    runner.invoke(app, ["install-skills", "--protect", "deep_analyzer"])
    # First install lands every skill (protection only applies to overwrites).
    runner.invoke(app, ["install-skills"])
    target = tmp_path / ".claude" / "skills" / "deep_analyzer" / "SKILL.md"
    assert target.is_file()
    # Tamper with the installed skill so we can detect overwrite vs preserve.
    target.write_text("CUSTOM USER VERSION\n", encoding="utf-8")
    # Re-install: protected skill must NOT be overwritten.
    result = runner.invoke(app, ["install-skills"])
    assert "skipped deep_analyzer" in result.stdout
    assert target.read_text() == "CUSTOM USER VERSION\n"


def test_taint_schema_init_seeds_from_example(tmp_path: Path) -> None:
    """``taint-schema --init`` copies the bundled example into the repo cache."""
    cache = tmp_path / "cache"
    cache.mkdir()
    repo = cache / "myrepo"
    repo.mkdir()
    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "taint-schema", "--repo-id", "myrepo", "--init"],
    )
    assert result.exit_code == 0
    schema = repo / "schema.taint.yml"
    assert schema.is_file()
    text = schema.read_text(encoding="utf-8")
    assert "llm_suggested:" in text
    assert "cache:user:*:profile" in text


def test_taint_schema_init_preserves_existing(tmp_path: Path) -> None:
    """Re-running ``--init`` does not clobber a hand-edited schema file."""
    cache = tmp_path / "cache"
    cache.mkdir()
    repo = cache / "myrepo"
    repo.mkdir()
    custom = repo / "schema.taint.yml"
    custom.write_text("custom: true\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "taint-schema", "--repo-id", "myrepo", "--init"],
    )
    assert result.exit_code == 0
    assert "already exists" in result.stdout
    assert custom.read_text() == "custom: true\n"
