"""Tests for ai_codescan.nominator orchestrator (queue construction)."""

import json
from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.nominator import build_queue


def _seed_flow(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute("INSERT INTO files VALUES ('/abs/x.ts', 'sha', 'ts', 'p', 100)")
    conn.execute(
        "INSERT INTO symbols VALUES ('S1', 'sym1', 'function', '/abs/x.ts', 1, 5, NULL, 'h')"
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', 'S1', 'http.body', 'name', '/abs/x.ts:2')"
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES "
        "('K1', 'S1', 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F1', 'T1', 'K1', 'CWE-89', 'codeql', '[]', '/sarif', 'definite')"
    )
    conn.execute("INSERT INTO entrypoints VALUES ('S1', 'http_route', 'app.post')")


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
