"""Tests for ai_codescan.recon — Phase 13 hunt-recon (git-history + feedback loop)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import duckdb

from ai_codescan.recon import (
    ReconHint,
    collect_recon_hints,
    confirmed_finding_files,
    security_fix_files,
    sibling_files,
    write_recon_hints,
)
from ai_codescan.review_verdicts import ReviewVerdict, persist_review_verdicts


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _make_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    repo_file = repo / "app" / "users.py"
    repo_file.write_text("# users\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.t")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fix: SQL injection in user lookup (CWE-89)")
    return repo


# --- sibling_files ------------------------------------------------------------


def test_sibling_files_finds_same_dir_same_ext(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    for name in ("users.py", "orders.py", "readme.md"):
        (tmp_path / "app" / name).write_text("x", encoding="utf-8")
    siblings = sibling_files("app/users.py", source_root=tmp_path)
    assert siblings == {"app/orders.py"}  # same ext, excludes self + the .md


def test_sibling_files_empty_for_non_code(tmp_path: Path) -> None:
    assert sibling_files("app/readme.md", source_root=tmp_path) == set()


# --- security_fix_files -------------------------------------------------------


def test_security_fix_files_finds_security_commit(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path)
    assert security_fix_files(repo) == {"app/users.py"}


def test_security_fix_files_empty_for_non_git_dir(tmp_path: Path) -> None:
    assert security_fix_files(tmp_path / "not-a-repo") == set()


def test_security_fix_files_ignores_non_security_commits(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.t")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "chore: rename a variable")
    assert security_fix_files(repo) == set()


# --- confirmed_finding_files --------------------------------------------------


def test_confirmed_finding_files_excludes_disputed(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    verdicts = [
        ReviewVerdict(
            "N-1",
            "F-keep",
            "fl",
            "c",
            "true-positive",
            "verified",
            "high",
            "CWE-89",
            "t",
            [],
            "deep_analyzer",
            "app/keep.py",
        ),
        ReviewVerdict(
            "N-2",
            "F-drop",
            "fl",
            "c",
            "true-positive",
            "verified",
            "high",
            "CWE-89",
            "t",
            [],
            "deep_analyzer",
            "app/drop.py",
        ),
        ReviewVerdict(
            "N-3",
            "F-fp",
            "fl",
            "c",
            "false-positive",
            "rejected",
            "high",
            "CWE-89",
            "t",
            [],
            "deep_analyzer",
            "app/fp.py",
        ),
    ]
    persist_review_verdicts(conn, verdicts)
    conn.execute(
        "CREATE TABLE adversarial_challenges "
        "(finding_id VARCHAR, original_verdict VARCHAR, original_reviewer VARCHAR, "
        "challenger_provider VARCHAR, result VARCHAR, rationale VARCHAR)"
    )
    # F-drop was disputed by a challenger — it no longer counts as confirmed.
    conn.execute(
        "INSERT INTO adversarial_challenges VALUES "
        "('F-drop', 'true-positive', 'deep_analyzer', 'gemini', 'disputed', '')"
    )
    assert confirmed_finding_files(conn) == {"app/keep.py"}


# --- collect_recon_hints ------------------------------------------------------


def test_collect_recon_hints_unions_both_sources(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path)
    # Sibling of the security-fix file, in the snapshot source root.
    (repo / "app" / "orders.py").write_text("# orders\n", encoding="utf-8")

    hints = collect_recon_hints(repo, source_root=repo, conn=None)
    files = {h.file for h in hints}
    assert "app/users.py" in files  # the security-fix file itself
    assert "app/orders.py" in files  # its sibling
    assert all(h.source == "git-history" for h in hints)


def test_collect_recon_hints_includes_feedback_loop(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path)
    # A confirmed finding in a directory NOT touched by any security-fix
    # commit — so its sibling is a pure feedback-loop hint.
    (repo / "lib").mkdir()
    (repo / "lib" / "payments.py").write_text("# payments\n", encoding="utf-8")
    (repo / "lib" / "refunds.py").write_text("# refunds\n", encoding="utf-8")
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    persist_review_verdicts(
        conn,
        [
            ReviewVerdict(
                "N-1",
                "F-1",
                "fl",
                "c",
                "true-positive",
                "verified",
                "high",
                "CWE-89",
                "t",
                [],
                "deep_analyzer",
                "lib/payments.py",
            ),
        ],
    )
    hints = collect_recon_hints(repo, source_root=repo, conn=conn)
    feedback = [h for h in hints if h.source == "feedback-loop"]
    # refunds.py is a sibling of the confirmed finding's file (lib/payments.py).
    assert any(h.file == "lib/refunds.py" for h in feedback)


def test_write_recon_hints_emits_jsonl(tmp_path: Path) -> None:
    hints = [
        ReconHint("app/a.py", "past security-fix file", "git-history"),
        ReconHint("app/b.py", "sibling of a confirmed finding", "feedback-loop"),
    ]
    out = write_recon_hints(hints, out_path=tmp_path / "recon_hints.jsonl")
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["source"] == "git-history"
