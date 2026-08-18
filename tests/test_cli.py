"""Tests for ai_codescan.cli."""

import json
import os
import re
from pathlib import Path

import duckdb
import pytest
from typer.testing import CliRunner

from ai_codescan import cli as cli_mod
from ai_codescan.cli import app
from ai_codescan.index.duckdb_schema import apply_schema

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
    assert "trusted source" in out


def test_eval_help_shows_run_command() -> None:
    result = runner.invoke(app, ["eval", "--help"])
    assert result.exit_code == 0
    out = _help_text(result.stdout)
    assert "run" in out
    assert "compare" in out


def test_eval_compare_writes_outputs(tmp_path: Path) -> None:
    ai = tmp_path / "ai.jsonl"
    ghost = tmp_path / "ghost.jsonl"
    out = tmp_path / "comparison"
    ai.write_text(
        '{"case_id":"case-1","status":"pass","matches":[],"false_positives":[]}\n',
        encoding="utf-8",
    )
    ghost.write_text(
        '{"case_id":"case-1","status":"miss","matches":[],"false_positives":[]}\n',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "eval",
            "compare",
            "--ai-results",
            str(ai),
            "--ghost-results",
            str(ghost),
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 0
    assert "ai-better=1" in result.stdout
    assert (out / "comparison.jsonl").is_file()
    assert (out / "comparison.md").is_file()


def test_candidates_handles_empty_scores(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    repo = cache / "repo-1"
    repo.mkdir(parents=True)
    db = repo / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.close()

    result = runner.invoke(app, ["--cache-dir", str(cache), "candidates", "--repo-id", "repo-1"])
    assert result.exit_code == 0
    assert "no scored candidates" in result.stdout


def test_candidates_supports_filters_and_all(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    repo = cache / "repo-1"
    repo.mkdir(parents=True)
    db = repo / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute(
        """
        INSERT INTO candidate_scores
          (
            candidate_id, flow_id, stream, score, label, processing_bucket,
            factors_json, scorer
          )
        VALUES
          ('N-high', 'F1', 'A', 0.9, 'high', 'report', '[]', 'test'),
          ('N-low', NULL, 'B', 0.3, 'low', 'explore', '[]', 'test')
        """
    )
    conn.close()

    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "candidates",
            "--repo-id",
            "repo-1",
            "--all",
            "--bucket",
            "explore",
        ],
    )

    assert result.exit_code == 0
    assert "N-low" in result.stdout
    assert "N-high" not in result.stdout
    assert "bucket" in result.stdout


def test_miss_review_gracefully_skips_without_llm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    repo = cache / "repo-1"
    repo.mkdir(parents=True)
    (repo / "miss_candidates.jsonl").write_text(
        '{"id":"B-miss-0001","score":0.5}\n',
        encoding="utf-8",
    )
    # miss-review needs a "latest run" dir to host model_proposals/findings —
    # see ai_codescan/miss_review.run_miss_review (Gemini 2026-05-15 wiring).
    (repo / "runs" / "test-run").mkdir(parents=True)
    monkeypatch.setenv("PATH", "/nonexistent")

    result = runner.invoke(app, ["--cache-dir", str(cache), "miss-review", "--repo-id", "repo-1"])

    assert result.exit_code == 0
    assert "LLM unavailable" in result.stdout
    assert (repo / "miss_review_queue.jsonl").is_file()


def test_analyze_auto_invokes_miss_review_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Phase 8: `analyze` runs miss-finder + miss-review at the end by
    default. With PATH cleared the LLM is unavailable, so miss-review
    stages the queue and skips — still printed in output."""
    monkeypatch.setenv("PATH", "/nonexistent")
    cache = tmp_path / "cache"
    repo = cache / "repo-1"
    repo.mkdir(parents=True)
    db_path = repo / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    conn.close()
    run_dir = repo / "runs" / "test-run"
    run_dir.mkdir(parents=True)
    (run_dir / "nominations.md").write_text("# Nominations\n", encoding="utf-8")
    (repo / "miss_candidates.jsonl").write_text(
        '{"id":"stale-candidate"}\n',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "analyze", "--repo-id", "repo-1"],
    )

    assert result.exit_code == 0, result.output
    assert "[miss-review]" in result.output
    # Miss-finder regenerated the queue instead of reusing the stale cache.
    assert (repo / "miss_candidates.jsonl").is_file()
    assert "stale-candidate" not in (repo / "miss_candidates.jsonl").read_text(encoding="utf-8")


def test_analyze_skip_miss_review_flag_skips_auto_invoke(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`analyze --skip-miss-review` keeps the legacy two-step workflow."""
    monkeypatch.setenv("PATH", "/nonexistent")
    cache = tmp_path / "cache"
    repo = cache / "repo-1"
    repo.mkdir(parents=True)
    db_path = repo / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    conn.close()
    run_dir = repo / "runs" / "test-run"
    run_dir.mkdir(parents=True)
    (run_dir / "nominations.md").write_text("# Nominations\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "analyze", "--repo-id", "repo-1", "--skip-miss-review"],
    )

    assert result.exit_code == 0, result.output
    assert "[miss-review]" not in result.output
    assert not (repo / "miss_candidates.jsonl").is_file()


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
    assert "--run-id" in out


def test_run_help_advertises_llm_flags() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    out = _help_text(result.stdout)
    assert "--llm-provider" in out
    assert "--llm-model" in out
    assert "trusted source" in out


def test_scan_help_warns_about_target_build_execution() -> None:
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "trusted source" in _help_text(result.stdout)


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
    run_id = f"orchestrator-{'a' * 64}"
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
            "gemini",
            "--llm-model",
            "gemini-2.5-pro",
            "--run-id",
            run_id,
        ],
    )
    assert result.exit_code == 0
    run_dir = cache / repo_id / "runs" / run_id
    run_json = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert run_json["llm_provider"] == "gemini"
    assert run_json["llm_model"] == "gemini-2.5-pro"

    other_run = cache / repo_id / "runs" / "other-run"
    other_run.mkdir()
    os.utime(run_dir, ns=(1_000_000_000, 1_000_000_000))
    os.utime(other_run, ns=(2_000_000_000, 2_000_000_000))
    result = runner.invoke(
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
            "--run-id",
            run_id,
        ],
    )
    assert result.exit_code == 0
    latest = max((cache / repo_id / "runs").iterdir(), key=lambda path: path.stat().st_mtime_ns)
    assert latest == run_dir


def test_nominate_rejects_unsafe_run_id(
    tmp_path: Path,
    fixtures_dir: Path,
) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(path.name for path in cache.iterdir() if path.is_dir())

    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "nominate",
            "--repo-id",
            repo_id,
            "--run-id",
            "../escape",
        ],
    )

    assert result.exit_code == 2
    assert "run id must contain" in result.output


def test_analyze_help_advertises_llm_flags() -> None:
    result = runner.invoke(app, ["analyze", "--help"])
    assert result.exit_code == 0
    out = _help_text(result.stdout)
    assert "--llm-provider" in out
    assert "--llm-model" in out
    assert "--max-candidates" in out
    assert "--max-llm-candidates" in out
    assert "--max-bundle-bytes" in out
    assert "--min-score" in out
    assert "--deterministic-only" in out


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


def test_scan_skip_hitl_runs_stages_in_order(tmp_path: Path, monkeypatch) -> None:
    """`scan --skip-hitl` chains the pipeline subcommands in order, with the
    gate stages auto-accepting via --yes (fully unattended)."""
    calls: list[list[str]] = []

    class _Result:
        returncode = 0

    def _fake_run(cmd, **_kw):
        calls.append(list(cmd))
        return _Result()

    monkeypatch.setattr(cli_mod.subprocess, "run", _fake_run)
    result = runner.invoke(
        app,
        ["--cache-dir", str(tmp_path), "scan", str(tmp_path / "src"), "--skip-hitl"],
    )
    assert result.exit_code == 0
    # The subcommand of each staged call, in order.
    stages = [c[c.index("--cache-dir") + 2] for c in calls]
    assert stages == [
        "prep",
        "nominate",
        "gate-1",
        "analyze",
        "gate-2",
        "taint-schema",  # Phase 17: storage_taint fixpoint -> stored XSS
        "validate",
        "gate-3",
        "report",
    ]
    assert calls[0][-2:] == ["--engine", "hybrid"]
    assert calls[0][calls[0].index("--llm-provider") : calls[0].index("--llm-provider") + 2] == [
        "--llm-provider",
        "claude",
    ]
    # Gates auto-accept under --skip-hitl.
    assert calls[2][-2:] == ["gate-1", "--yes"]
    assert calls[4][-2:] == ["gate-2", "--yes"]
    assert calls[7][-2:] == ["gate-3", "--yes"]
    # The report stage emits HTML.
    assert "--html" in calls[8]


def test_scan_forwards_codex_provider_and_model_to_llm_heavy_prep(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[list[str]] = []

    class _Result:
        returncode = 0

    monkeypatch.setattr(
        cli_mod.subprocess,
        "run",
        lambda cmd, **_kwargs: calls.append(list(cmd)) or _Result(),
    )
    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(tmp_path),
            "scan",
            str(tmp_path / "src"),
            "--skip-hitl",
            "--engine",
            "llm-heavy",
            "--llm-provider",
            "codex",
            "--llm-model",
            "gpt-5.6",
        ],
    )

    assert result.exit_code == 0
    prep_call = calls[0]
    assert "--engine" in prep_call and prep_call[prep_call.index("--engine") + 1] == "llm-heavy"
    assert prep_call[prep_call.index("--llm-provider") + 1] == "codex"
    assert prep_call[prep_call.index("--llm-model") + 1] == "gpt-5.6"


def test_scan_aborts_when_a_fatal_stage_fails(tmp_path: Path, monkeypatch) -> None:
    """A non-zero exit from a fatal stage (prep) stops the pipeline."""
    calls: list[str] = []

    class _Fail:
        returncode = 1

    def _fake_run(cmd, **_kw):
        calls.append(cmd[cmd.index("--cache-dir") + 2])
        return _Fail()

    monkeypatch.setattr(cli_mod.subprocess, "run", _fake_run)
    result = runner.invoke(app, ["--cache-dir", str(tmp_path), "scan", ".", "--skip-hitl"])
    assert result.exit_code == 1
    # prep failed -> pipeline stops, nominate never runs.
    assert calls == ["prep"]


def test_scan_validate_failure_is_non_fatal(tmp_path: Path, monkeypatch) -> None:
    """A host without Docker fails `validate`, but the scan still completes
    through to the report stage."""
    stages: list[str] = []

    def _fake_run(cmd, **_kw):
        stage = cmd[cmd.index("--cache-dir") + 2]
        stages.append(stage)

        class _R:
            returncode = 1 if stage == "validate" else 0

        return _R()

    monkeypatch.setattr(cli_mod.subprocess, "run", _fake_run)
    result = runner.invoke(app, ["--cache-dir", str(tmp_path), "scan", ".", "--skip-hitl"])
    assert result.exit_code == 0
    assert "report" in stages  # reached the end despite validate failing
