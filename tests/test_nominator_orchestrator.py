"""Tests for ai_codescan.nominator orchestrator (queue construction)."""

import json
from pathlib import Path

import duckdb
import pytest

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.nominator import build_queue, run_nominator
from ai_codescan.runs.state import load_or_create
from ai_codescan.taxonomy.loader import resolve_classes


def _seed_flow(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute("INSERT INTO files VALUES ('/abs/x.ts', 'sha', 'ts', 'p', 100)")
    conn.execute(
        "INSERT INTO symbols VALUES ('S1', 'sym1', 'function', '/abs/x.ts', 1, 5, NULL, 'h')"
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', 'S1', 'http.body', 'name', '/abs/x.ts:2')"
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', 'S1', 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F1', 'T1', 'K1', 'CWE-89', 'codeql', '[]', '/sarif', 'definite')"
    )
    conn.execute("INSERT INTO entrypoints VALUES ('S1', 'http_route', 'app.post', '/abs/x.ts', 1)")


def test_build_queue_includes_stream_a_for_each_flow(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_flow(conn)
    queue = build_queue(conn, target_bug_classes=["sqli"])
    streams = {q["stream"] for q in queue}
    assert "A" in streams
    flow_records = [q for q in queue if q["stream"] == "A"]
    assert flow_records[0]["fid"] == "F1"


def test_build_queue_filters_by_bug_class(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_flow(conn)
    queue = build_queue(conn, target_bug_classes=["xss"])
    flow_records = [q for q in queue if q["stream"] == "A"]
    assert flow_records == []  # CWE-89 is not in xss class


def test_build_queue_serialises_as_jsonl(tmp_path: Path) -> None:
    db = tmp_path / "z.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_flow(conn)
    queue = build_queue(conn, target_bug_classes=["sqli"])
    out = tmp_path / "queue.jsonl"
    out.write_text("\n".join(json.dumps(q) for q in queue))
    parsed = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    assert parsed == queue


def test_build_queue_hashes_unsafe_scip_symbol_ids(tmp_path: Path) -> None:
    db = tmp_path / "scip.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    symbol_id = "scip:scip-java maven . . pkg/AuthGuard#requireAdmin()."
    conn.execute(
        "INSERT INTO symbols VALUES (?, 'sym', 'function', '/abs/Auth.kt', 1, 1, "
        "NULL, 'requireAdmin')",
        [symbol_id],
    )

    queue = build_queue(conn, target_bug_classes=[])

    candidate = next(item for item in queue if item["concern"] == "authz-callsite")
    assert candidate["id"].startswith("B-auth-h-")
    assert "/" not in candidate["id"]
    assert candidate["symbol_id"] == symbol_id


def test_build_queue_hashes_unsafe_flow_and_sink_ids(tmp_path: Path) -> None:
    db = tmp_path / "unsafe-flow-ids.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    tid = "../../../source"
    flow_sid = "../../../flow-sink"
    flow_id = "../../../outside"
    sink_only_id = "../../../sink-only"
    conn.execute(
        "INSERT INTO taint_sources VALUES (?, NULL, 'http.body', 'id', '/abs/x.ts:1')",
        [tid],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES (?, NULL, 'sql.exec', 'query', 'unknown', '[]')",
        [flow_sid],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES (?, NULL, 'sql.exec', 'query', 'unknown', '[]')",
        [sink_only_id],
    )
    conn.execute(
        "INSERT INTO flows VALUES (?, ?, ?, 'CWE-89', 'llm-heavy', '[]', '', 'inferred')",
        [flow_id, tid, flow_sid],
    )

    queue = build_queue(conn, target_bug_classes=[])

    flow = next(item for item in queue if item.get("fid") == flow_id)
    sink = next(item for item in queue if item.get("sink_id") == sink_only_id)
    assert flow["id"].startswith("A-h-")
    assert sink["id"].startswith("B-sink-h-")
    assert all("/" not in item["id"] and ".." not in item["id"] for item in (flow, sink))


def test_run_nominator_stages_scores_and_bundles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "repo.md").write_text("# Repo\n", encoding="utf-8")
    (repo_dir / "entrypoints.md").write_text("# Entrypoints\n", encoding="utf-8")
    source = repo_dir / "source"
    source.mkdir()
    source_file = source / "x.ts"
    source_file.write_text("const id = req.body.id\nawait db.query(id)\n", encoding="utf-8")

    db = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [source_file.as_posix()])
    conn.execute(
        "INSERT INTO symbols VALUES ('S1', 'sym1', 'function', ?, 1, 2, NULL, 'handler')",
        [source_file.as_posix()],
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', 'S1', 'http.body', 'id', ?)",
        [f"{source_file}:1"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', 'S1', 'sql.exec', 'query', 'unknown', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif', 'definite')",
        [json.dumps([[source_file.as_posix(), 1], [source_file.as_posix(), 2]])],
    )
    conn.execute(
        "INSERT INTO entrypoints VALUES ('S1', 'http_route', 'app.post', ?, 1)",
        [source_file.as_posix()],
    )
    conn.close()

    state = load_or_create(repo_dir, engine="codeql", temperature=0.0, target_bug_classes=["sqli"])
    monkeypatch.setenv("PATH", "/nonexistent")

    nominations = run_nominator(
        state,
        repo_dir=repo_dir,
        bug_classes=resolve_classes(["sqli"]),
        db_path=db,
    )

    assert nominations.is_file()
    queued = [
        json.loads(line)
        for line in (state.run_dir / "queue.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert queued[0]["score_label"] in {"medium", "high"}
    assert Path(queued[0]["bundle_json"]).is_file()
    conn = duckdb.connect(str(db), read_only=True)
    try:
        row = conn.execute(
            "SELECT label FROM candidate_scores WHERE candidate_id = 'A-F1'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None

    done_dir = state.run_dir / ".done"
    done_dir.mkdir()
    (done_dir / "A-F1").write_text("old-default-model", encoding="utf-8")
    nominations.write_text("# Nominations\n\nold default-model output\n", encoding="utf-8")

    run_nominator(
        state,
        repo_dir=repo_dir,
        bug_classes=resolve_classes(["sqli"]),
        db_path=db,
    )

    assert "old default-model output" not in nominations.read_text(encoding="utf-8")
    assert not (done_dir / "A-F1").exists()
