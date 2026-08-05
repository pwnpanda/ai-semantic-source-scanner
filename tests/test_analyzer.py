"""Tests for ai_codescan.analyzer (orchestrator surface)."""

from pathlib import Path
from unittest.mock import MagicMock

import duckdb
import pytest

from ai_codescan.analyzer import (
    ReviewLimits,
    _limit_review_items,
    _pick_flow_for_nomination,
    run_analyzer,
)
from ai_codescan.findings.queue import QueueItem
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.runs.state import load_or_create


def _seed(conn: duckdb.DuckDBPyConnection, file: str) -> None:
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [file])
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', NULL, 'http.body', 'name', ?)",
        [f"{file}:2"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    steps = f'[["{file}", 2, 2], ["{file}", 5, 5]]'
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif', 'definite')",
        [steps],
    )


def _seed_two_flows_same_file(conn: duckdb.DuckDBPyConnection, file: str) -> None:
    """Seed two flows whose sources sit on different lines of the same file."""
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [file])
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T-42', NULL, 'http.body', 'a', ?)",
        [f"{file}:42"],
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T-50', NULL, 'http.body', 'b', ?)",
        [f"{file}:50"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    steps_42 = f'[["{file}", 42, 42], ["{file}", 60, 60]]'
    steps_50 = f'[["{file}", 50, 50], ["{file}", 70, 70]]'
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F-42', 'T-42', 'K1', 'CWE-89', 'codeql', ?, '/sarif', 'definite')",
        [steps_42],
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F-50', 'T-50', 'K1', 'CWE-89', 'codeql', ?, '/sarif', 'definite')",
        [steps_50],
    )


def test_pick_flow_exact_match_wins_over_substring(tmp_path: Path) -> None:
    """source_loc points to line 50 → must resolve to F-50, not F-42."""
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    file = "/abs/users.ts"
    _seed_two_flows_same_file(conn, file)

    fid = _pick_flow_for_nomination(conn, {"source_loc": f"{file}:50"})
    assert fid == "F-50"

    fid_42 = _pick_flow_for_nomination(conn, {"source_loc": f"{file}:42"})
    assert fid_42 == "F-42"
    conn.close()


def test_pick_flow_stream_a_uses_fid_directly() -> None:
    """Stream A nomination with `fid` returns it without touching the DB."""
    fake_conn = MagicMock(spec=duckdb.DuckDBPyConnection)
    fid = _pick_flow_for_nomination(
        fake_conn,
        {"stream": "A", "fid": "F-1", "source_loc": "/abs/users.ts:42"},
    )
    assert fid == "F-1"
    fake_conn.execute.assert_not_called()


def test_pick_flow_stream_b_falls_back_via_file_hint(tmp_path: Path) -> None:
    """Stream B authz-callsite nomination resolves via file hint when a flow exists."""
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)

    nomination = {
        "stream": "B",
        "concern": "authz-callsite",
        "file": "/abs/orders.ts",
        "line": 58,
    }

    # No flow yet → None.
    assert _pick_flow_for_nomination(conn, nomination) is None

    # Seed a flow rooted in /abs/orders.ts → file-hint fallback finds it.
    _seed(conn, "/abs/orders.ts")
    assert _pick_flow_for_nomination(conn, nomination) == "F1"
    conn.close()


def test_limit_review_items_filters_scores_without_dropping_unscored(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute(
        """
        INSERT INTO candidate_scores
          (candidate_id, flow_id, stream, score, label, factors_json, scorer)
        VALUES
          ('N-low', NULL, 'B', 0.1, 'probably-safe', '[]', 'test'),
          ('N-high', NULL, 'A', 0.9, 'high', '[]', 'test')
        """
    )
    items = [
        QueueItem("N-low", "api", "sqli", "/x:1"),
        QueueItem("N-high", "api", "sqli", "/x:2"),
        QueueItem("N-unscored", "api", "sqli", "/x:3"),
    ]

    filtered = _limit_review_items(conn, items, min_score=0.5)

    assert [item.nomination_id for item in filtered] == ["N-high", "N-unscored"]
    conn.close()


def test_limit_review_items_caps_by_score(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute(
        """
        INSERT INTO candidate_scores
          (candidate_id, flow_id, stream, score, label, factors_json, scorer)
        VALUES
          ('N-a', NULL, 'A', 0.4, 'low', '[]', 'test'),
          ('N-b', NULL, 'A', 0.8, 'high', '[]', 'test')
        """
    )
    items = [
        QueueItem("N-a", "api", "sqli", "/x:1"),
        QueueItem("N-b", "api", "sqli", "/x:2"),
    ]

    filtered = _limit_review_items(conn, items, max_candidates=1)

    assert [item.nomination_id for item in filtered] == ["N-b"]
    conn.close()


def test_run_analyzer_writes_queue_and_slices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    src_dir = repo_dir / "source"
    src_dir.mkdir()
    src_file = src_dir / "x.ts"
    src_file.write_text("// 1\nconst id = req.body.name\n// 3\n// 4\nawait db.query(`x ${id}`)\n")

    db = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn, str(src_file))
    conn.close()

    state = load_or_create(repo_dir, engine="codeql", temperature=0.0, target_bug_classes=["sqli"])
    # The QueueItem.loc field carries the exact source_loc (file:line).
    nomination_loc = f"{src_file}:2"
    (state.run_dir / "nominations.md").write_text(
        "# Nominations\n\n## Stream A\n\n"
        f"- [ ] N-001 | api | sqli | {nomination_loc} | rec: high | y/n: y\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("PATH", "/nonexistent")
    queue_path = run_analyzer(state, repo_dir=repo_dir, db_path=db)
    assert queue_path.is_file()
    queue_text = queue_path.read_text(encoding="utf-8")
    assert "N-001" in queue_text
    slice_file = state.run_dir / "slices" / "N-001.json"
    assert slice_file.is_file()
    bundle_file = state.run_dir / "bundles" / "N-001.json"
    assert bundle_file.is_file()
    findings_dir = state.run_dir / "findings"
    assert findings_dir.is_dir()


def test_run_analyzer_truncates_large_bundles_without_dropping_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recall-First Invariant 4: --max-bundle-bytes truncates the bundle on disk,
    but the candidate stays in the LLM review queue."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    src_dir = repo_dir / "source"
    src_dir.mkdir()
    src_file = src_dir / "x.ts"
    src_file.write_text("const id = req.body.name\nawait db.query(`x ${id}`)\n")

    db = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn, str(src_file))
    conn.close()

    state = load_or_create(repo_dir, engine="codeql", temperature=0.0, target_bug_classes=["sqli"])
    nomination_loc = f"{src_file}:2"
    (state.run_dir / "nominations.md").write_text(
        "# Nominations\n\n## Stream A\n\n"
        f"- [ ] N-001 | api | sqli | {nomination_loc} | rec: high | y/n: y\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("PATH", "/nonexistent")
    # First write a no-cap bundle so we can compare sizes.
    queue_path_full = run_analyzer(
        state,
        repo_dir=repo_dir,
        db_path=db,
        limits=ReviewLimits(),
    )
    full_size = (state.run_dir / "bundles" / "N-001.json").stat().st_size
    cap = max(1, full_size - 200)  # cap is below full size so truncation must engage
    queue_path = run_analyzer(
        state,
        repo_dir=repo_dir,
        db_path=db,
        limits=ReviewLimits(max_bundle_bytes=cap),
    )
    assert queue_path == queue_path_full  # same run_dir

    queue_text = queue_path.read_text(encoding="utf-8")
    assert "N-001" in queue_text, "candidate must remain in LLM queue (Invariant 4)"
    bundle_path = state.run_dir / "bundles" / "N-001.json"
    assert bundle_path.is_file()
    assert bundle_path.stat().st_size < full_size, (
        f"bundle was not truncated: size={bundle_path.stat().st_size} full={full_size}"
    )
    # Bundle annotates that it was truncated (Invariant 4 visibility).
    bundle_payload = bundle_path.read_text(encoding="utf-8")
    assert "bundle.truncated" in bundle_payload


def test_run_analyzer_no_default_size_cap_keeps_full_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No --max-bundle-bytes set: bundle is written full-size, candidate is queued."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    src_dir = repo_dir / "source"
    src_dir.mkdir()
    src_file = src_dir / "x.ts"
    src_file.write_text("const id = req.body.name\nawait db.query(`x ${id}`)\n")

    db = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn, str(src_file))
    conn.close()

    state = load_or_create(repo_dir, engine="codeql", temperature=0.0, target_bug_classes=["sqli"])
    nomination_loc = f"{src_file}:2"
    (state.run_dir / "nominations.md").write_text(
        "# Nominations\n\n## Stream A\n\n"
        f"- [ ] N-001 | api | sqli | {nomination_loc} | rec: high | y/n: y\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("PATH", "/nonexistent")
    queue_path = run_analyzer(
        state,
        repo_dir=repo_dir,
        db_path=db,
        limits=ReviewLimits(),  # default: no cap
    )

    queue_text = queue_path.read_text(encoding="utf-8")
    assert "N-001" in queue_text
    bundle_path = state.run_dir / "bundles" / "N-001.json"
    assert bundle_path.is_file()
    # No cap → bundle should retain excerpts (>200 bytes for a real candidate).
    assert bundle_path.stat().st_size > 200


def test_run_analyzer_deterministic_only_skips_llm_when_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    src_dir = repo_dir / "source"
    src_dir.mkdir()
    src_file = src_dir / "x.ts"
    src_file.write_text("const id = req.body.name\nawait db.query(`x ${id}`)\n")

    db = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn, str(src_file))
    conn.close()

    state = load_or_create(repo_dir, engine="codeql", temperature=0.0, target_bug_classes=["sqli"])
    nomination_loc = f"{src_file}:2"
    (state.run_dir / "nominations.md").write_text(
        "# Nominations\n\n## Stream A\n\n"
        f"- [ ] N-001 | api | sqli | {nomination_loc} | rec: high | y/n: y\n",
        encoding="utf-8",
    )
    run_called = False

    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        nonlocal run_called
        run_called = True
        raise AssertionError("LLM loop should not run")

    monkeypatch.setattr("ai_codescan.analyzer.is_available", lambda _provider: True)
    monkeypatch.setattr("ai_codescan.analyzer.subprocess.run", fail_if_called)

    queue_path = run_analyzer(
        state,
        repo_dir=repo_dir,
        db_path=db,
        limits=ReviewLimits(deterministic_only=True),
    )

    assert queue_path.is_file()
    assert not run_called
