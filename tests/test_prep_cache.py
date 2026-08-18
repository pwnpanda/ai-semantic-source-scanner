"""Regression tests for transactional prep and fingerprinted cache reuse."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterable, Iterator
from pathlib import Path

import duckdb
import pytest

from ai_codescan import prep as prep_mod
from ai_codescan.ast.runner import AstJob
from ai_codescan.cache_state import (
    _scanner_files,
    build_scan_fingerprint,
    scan_db_stage,
    scan_db_stage_is_current,
    set_scan_stage,
)
from ai_codescan.config import compute_repo_id
from ai_codescan.prep import run_prep
from ai_codescan.repo_lock import RepoScanLockedError, repo_scan_lock


def _write_node_target(target: Path, source: str) -> None:
    target.mkdir(exist_ok=True)
    (target / "package.json").write_text('{"name":"cache-test"}\n', encoding="utf-8")
    (target / "app.js").write_text(source, encoding="utf-8")


def _ast_file_records(jobs: Iterable[AstJob]) -> Iterator[dict[str, object]]:
    for job in jobs:
        for path in job.files:
            yield {
                "type": "file",
                "file": path.as_posix(),
                "lang": job.kind,
                "lineCount": 1,
            }


def _patch_local_indexers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ai_codescan.prep._build_scip_lookup", lambda *_args: ({}, False))
    monkeypatch.setattr(
        "ai_codescan.prep._run_codeql_for_projects",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr("ai_codescan.prep.run_jobs", _ast_file_records)


def _insert_review(conn: duckdb.DuckDBPyConnection, review_id: str) -> None:
    conn.execute(
        """
        INSERT INTO review_verdicts
          (nomination_id, verdict, status, reviewer, evidence_json)
        VALUES (?, 'confirmed', 'accepted', 'test', '{}')
        """,
        [review_id],
    )


def test_failed_rebuild_rolls_back_and_retry_rebuilds_matching_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    cache_root = tmp_path / "cache"
    _write_node_target(target, "export const version = 1;\n")
    monkeypatch.setattr("ai_codescan.prep._build_scip_lookup", lambda *_args: ({}, False))
    monkeypatch.setattr("ai_codescan.prep.run_jobs", _ast_file_records)

    _first, db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    conn = duckdb.connect(str(db_path))
    old_row = conn.execute("SELECT sha256 FROM files WHERE path LIKE '%app.js'").fetchone()
    assert old_row is not None
    old_sha = str(old_row[0])
    cache_row = conn.execute("SELECT fingerprint FROM scan_cache_state").fetchone()
    assert cache_row is not None
    old_fingerprint = str(cache_row[0])
    _insert_review(conn, "review-survives")
    conn.close()

    (target / "app.js").write_text("export const version = 2;\n", encoding="utf-8")

    def fail_ast(_jobs: Iterable[AstJob]) -> Iterator[dict[str, object]]:
        raise RuntimeError("synthetic AST failure after source-table clear")
        yield

    monkeypatch.setattr("ai_codescan.prep.run_jobs", fail_ast)
    with pytest.raises(RuntimeError, match="synthetic AST failure"):
        run_prep(
            target,
            cache_root=cache_root,
            engine="none",
            bug_classes=[],
            quiet=True,
        )

    repo_dir = db_path.parent
    assert (repo_dir / ".prep-incomplete").is_file()
    assert not scan_db_stage_is_current(
        db_path,
        fingerprint=old_fingerprint,
        engine="none",
        required_stage="complete",
    )
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        assert conn.execute("SELECT sha256 FROM files WHERE path LIKE '%app.js'").fetchone() == (
            old_sha,
        )
        assert conn.execute("SELECT COUNT(*) FROM review_verdicts").fetchone() == (1,)
    finally:
        conn.close()

    monkeypatch.setattr("ai_codescan.prep.run_jobs", _ast_file_records)
    retry, _db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )

    expected_sha = hashlib.sha256(b"export const version = 2;\n").hexdigest()
    assert retry.skipped is True
    assert retry.index_reused is False
    assert not (repo_dir / ".prep-incomplete").exists()
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        assert conn.execute("SELECT sha256 FROM files WHERE path LIKE '%app.js'").fetchone() == (
            expected_sha,
        )
        assert conn.execute("SELECT COUNT(*) FROM review_verdicts").fetchone() == (1,)
    finally:
        conn.close()


def test_concurrent_prep_fails_before_touching_owner_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    cache_root = tmp_path / "cache"
    _write_node_target(target, "export const version = 1;\n")
    _patch_local_indexers(monkeypatch)
    repo_dir = cache_root / compute_repo_id(target)
    repo_dir.mkdir(parents=True)
    marker = repo_dir / ".prep-incomplete"
    marker.write_text("owner still running\n", encoding="utf-8")
    acquired = threading.Event()
    release = threading.Event()

    def hold_repo_lock() -> None:
        with repo_scan_lock(repo_dir):
            acquired.set()
            assert release.wait(timeout=5)

    owner = threading.Thread(target=hold_repo_lock)
    owner.start()
    assert acquired.wait(timeout=5)
    try:
        with pytest.raises(RepoScanLockedError, match="scan already in progress"):
            run_prep(
                target,
                cache_root=cache_root,
                engine="none",
                bug_classes=[],
                quiet=True,
            )
        assert marker.read_text(encoding="utf-8") == "owner still running\n"
        assert not (repo_dir / "index.duckdb").exists()
    finally:
        release.set()
        owner.join(timeout=5)
    assert not owner.is_alive()

    _snapshot, db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    assert db_path.is_file()
    assert not marker.exists()


def test_prep_marker_remains_until_post_commit_artifacts_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    cache_root = tmp_path / "cache"
    _write_node_target(target, "export const version = 1;\n")
    _patch_local_indexers(monkeypatch)
    _first, db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    (target / "app.js").write_text("export const version = 2;\n", encoding="utf-8")
    promote = prep_mod._promote_index_artifacts

    def fail_promote(_artifact_root: Path, _repo_dir: Path) -> None:
        raise RuntimeError("synthetic publish failure")

    monkeypatch.setattr("ai_codescan.prep._promote_index_artifacts", fail_promote)

    with pytest.raises(RuntimeError, match="synthetic publish failure"):
        run_prep(
            target,
            cache_root=cache_root,
            engine="none",
            bug_classes=[],
            quiet=True,
        )

    marker = db_path.parent / ".prep-incomplete"
    assert marker.is_file()
    monkeypatch.setattr("ai_codescan.prep._promote_index_artifacts", promote)
    retry, _db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    assert retry.skipped is True
    assert retry.index_reused is False
    assert not marker.exists()


def test_available_codeql_failure_rolls_back_and_retry_is_not_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    cache_root = tmp_path / "cache"
    _write_node_target(target, "export const version = 1;\n")
    monkeypatch.setattr("ai_codescan.prep._build_scip_lookup", lambda *_args: ({}, False))
    monkeypatch.setattr("ai_codescan.prep.run_jobs", _ast_file_records)
    _first, db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    conn = duckdb.connect(str(db_path), read_only=True)
    old_rows = conn.execute("SELECT COUNT(*) FROM files").fetchone()
    conn.close()

    monkeypatch.setattr(
        "ai_codescan.prep.shutil.which",
        lambda tool: "/fake/codeql" if tool == "codeql" else None,
    )

    def fail_database(*_args, **_kwargs):
        raise RuntimeError("query setup failed")

    monkeypatch.setattr("ai_codescan.prep.build_database", fail_database)
    with pytest.raises(RuntimeError, match="codeql failed.*query setup failed"):
        run_prep(
            target,
            cache_root=cache_root,
            engine="codeql",
            bug_classes=[],
            quiet=True,
        )

    marker = db_path.parent / ".prep-incomplete"
    assert marker.is_file()
    conn = duckdb.connect(str(db_path), read_only=True)
    assert conn.execute("SELECT COUNT(*) FROM files").fetchone() == old_rows
    conn.close()

    monkeypatch.setattr(
        "ai_codescan.prep._run_codeql_for_projects",
        lambda *_args, **_kwargs: False,
    )
    retry, _db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="codeql",
        bug_classes=[],
        quiet=True,
    )
    assert retry.skipped is True
    assert retry.index_reused is False
    assert not marker.exists()


def test_available_scip_failure_remains_retryable_without_aborting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    cache_root = tmp_path / "cache"
    _write_node_target(target, "export const version = 1;\n")
    _patch_local_indexers(monkeypatch)
    monkeypatch.setattr("ai_codescan.prep._build_scip_lookup", lambda *_args: ({}, True))

    first, db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    second, _db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )

    assert first.index_reused is False
    assert second.skipped is True
    assert second.index_reused is False
    assert scan_db_stage(db_path) == "complete_with_gaps"


def test_rule_fingerprint_change_removes_old_flow_but_preserves_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    cache_root = tmp_path / "cache"
    _write_node_target(target, "export const value = request.query.value;\n")
    _patch_local_indexers(monkeypatch)
    repo_dir = cache_root / compute_repo_id(target)
    repo_dir.mkdir(parents=True)
    extension_path = repo_dir / "aics-joern-extension-packs.json"
    extension_path.write_text(
        json.dumps({"sinks": [{"language": "javascript", "sink_pattern": "oldSink"}]}),
        encoding="utf-8",
    )

    _first, db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="hybrid",
        bug_classes=[],
        quiet=True,
    )
    old_fingerprint = build_scan_fingerprint(repo_dir, engine="hybrid", bug_classes=[])
    conn = duckdb.connect(str(db_path))
    conn.execute("INSERT INTO taint_sources VALUES ('T-old', NULL, 'input', 'q', 'app.js:1')")
    conn.execute("INSERT INTO taint_sinks VALUES ('S-old', NULL, 'exec', 'oldSink', '', '[]')")
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F-old', 'T-old', 'S-old', 'CWE-78', 'joern', '[]', '', 'inferred')"
    )
    _insert_review(conn, "durable-review")
    set_scan_stage(
        conn,
        fingerprint=old_fingerprint,
        engine="hybrid",
        stage="complete",
    )
    conn.close()

    extension_path.write_text(json.dumps({"sinks": []}), encoding="utf-8")
    second, _db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="hybrid",
        bug_classes=[],
        quiet=True,
    )

    assert second.skipped is True
    assert second.index_reused is False
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM flows WHERE fid = 'F-old'").fetchone() == (0,)
        assert conn.execute("SELECT COUNT(*) FROM review_verdicts").fetchone() == (1,)
    finally:
        conn.close()


def test_tool_availability_changes_scan_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "manifest.jsonl").write_text("", encoding="utf-8")
    monkeypatch.setattr("ai_codescan.cache_state.shutil.which", lambda _tool: None)
    missing = build_scan_fingerprint(repo_dir, engine="hybrid", bug_classes=[])

    semgrep = tmp_path / "semgrep"
    semgrep.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        "ai_codescan.cache_state.shutil.which",
        lambda tool: str(semgrep) if tool == "semgrep" else None,
    )
    available = build_scan_fingerprint(repo_dir, engine="hybrid", bug_classes=[])

    assert available != missing


def test_fingerprint_hashes_promoted_rules_but_excludes_staged_rules(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    active = repo_dir / ".semgrep" / "rules"
    staged = repo_dir / ".semgrep" / "rules.staged"
    active.mkdir(parents=True)
    staged.mkdir(parents=True)
    (repo_dir / "manifest.jsonl").write_text("", encoding="utf-8")
    staged_rule = staged / "candidate.yml"
    staged_rule.write_text("rules: []\n", encoding="utf-8")
    initial = build_scan_fingerprint(repo_dir, engine="hybrid", bug_classes=[])

    staged_rule.write_text("rules:\n  - id: still-unapproved\n", encoding="utf-8")
    after_staged_change = build_scan_fingerprint(repo_dir, engine="hybrid", bug_classes=[])
    (active / "promoted.yml").write_text("rules:\n  - id: approved\n", encoding="utf-8")
    after_promotion = build_scan_fingerprint(repo_dir, engine="hybrid", bug_classes=[])

    assert after_staged_change == initial
    assert after_promotion != initial


def test_llm_provider_and_model_change_llm_heavy_fingerprint(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "manifest.jsonl").write_text("", encoding="utf-8")
    claude = build_scan_fingerprint(
        repo_dir,
        engine="llm-heavy",
        bug_classes=[],
        engine_config={"llm_provider": "claude", "llm_model": "opus"},
    )
    codex = build_scan_fingerprint(
        repo_dir,
        engine="llm-heavy",
        bug_classes=[],
        engine_config={"llm_provider": "codex", "llm_model": "gpt-5.6"},
    )

    assert codex != claude


def test_scanner_fingerprint_inputs_include_llm_markdown_prompts(tmp_path: Path) -> None:
    prompt = tmp_path / "skills" / "llm-heavy" / "walker.md"
    prompt.parent.mkdir(parents=True)
    prompt.write_text("first prompt\n", encoding="utf-8")

    assert list(_scanner_files(tmp_path)) == [prompt]


@pytest.mark.parametrize("initialized", (False, True))
def test_scan_db_stage_is_current_rejects_invalid_databases(
    tmp_path: Path,
    initialized: bool,
) -> None:
    db_path = tmp_path / "index.duckdb"
    if initialized:
        duckdb.connect(str(db_path)).close()
    else:
        db_path.write_bytes(b"not a DuckDB database")

    assert not scan_db_stage_is_current(
        db_path,
        fingerprint="requested-inputs",
        engine="hybrid",
        required_stage="complete",
    )
