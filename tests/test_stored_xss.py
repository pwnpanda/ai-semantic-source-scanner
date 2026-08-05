"""Tests for ai_codescan.stored_xss — synthetic stored-XSS flow emission."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.stored_xss import SYNTHETIC_ENGINE, synthesize_stored_xss_flows


def _conn(tmp_path: Path) -> duckdb.DuckDBPyConnection:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    return conn


def _seed_storage_taint_and_write(  # noqa: PLR0913 - test-helper plumbing, intentionally explicit
    conn: duckdb.DuckDBPyConnection,
    *,
    storage_id: str = "table.comments",
    source_tid: str = "T-http-1",
    source_loc: str = "server.js:7",
    derived_tid: str = "T-stored-aa11",
    write_fid: str = "f-write-1",
    write_file: str = "server.js",
) -> None:
    conn.execute(
        "INSERT INTO taint_sources VALUES (?, ?, ?, ?, ?)",
        [source_tid, None, "http.request", "req.body", source_loc],
    )
    write_steps = json.dumps([[write_file, 7, 7], [write_file, 8, 8]])
    conn.execute(
        "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [write_fid, source_tid, "S-write-1", "CWE-89", "joern", write_steps, None, "high"],
    )
    conn.execute(
        "INSERT INTO storage_writes VALUES (?, ?, ?, ?, ?)",
        [storage_id, write_fid, source_tid, None, json.dumps({"shape": "sql"})],
    )
    conn.execute(
        "INSERT INTO storage_taint VALUES (?, ?, ?, ?)",
        [storage_id, derived_tid, json.dumps([source_tid]), "definite"],
    )


def _seed_read_and_xss_sink(  # noqa: PLR0913 - test-helper plumbing, intentionally explicit
    conn: duckdb.DuckDBPyConnection,
    *,
    storage_id: str = "table.comments",
    read_symbol: str = "sym-read-1",
    read_file: str = "server.js",
    xss_sink_file: str | None = None,
    xss_sink_line: int = 22,
) -> None:
    sink_file = xss_sink_file or read_file
    conn.execute(
        "INSERT INTO symbols VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [read_symbol, "fetchComments", "function", read_file, 15, 30, None, None],
    )
    conn.execute(
        "INSERT INTO storage_reads VALUES (?, ?, ?)",
        [storage_id, read_symbol, None],
    )
    xss_steps = json.dumps([[sink_file, 20, 20], [sink_file, xss_sink_line, xss_sink_line]])
    conn.execute(
        "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ["f-xss-1", "T-some", "S-xss-1", "CWE-79", "joern", xss_steps, None, "high"],
    )


def test_synthesizes_stored_xss_flow_for_same_file_render(tmp_path: Path) -> None:
    conn = _conn(tmp_path)
    _seed_storage_taint_and_write(conn)
    _seed_read_and_xss_sink(conn)

    added = synthesize_stored_xss_flows(conn)
    assert added == 1

    row = conn.execute(
        "SELECT fid, cwe, engine, confidence, steps_json FROM flows WHERE engine = ?",
        [SYNTHETIC_ENGINE],
    ).fetchone()
    assert row is not None
    assert row[1] == "CWE-79"
    assert row[3] == "inferred"
    steps = json.loads(row[4])
    # 4-step chain: original-source -> write-site -> read-site -> render-sink.
    assert len(steps) == 4
    # First step credits the original request source.
    assert steps[0][0] == "server.js"
    # Last step is the XSS sink line.
    assert steps[3][2] == 22


def test_no_flow_when_xss_sink_is_in_a_different_file(tmp_path: Path) -> None:
    conn = _conn(tmp_path)
    _seed_storage_taint_and_write(conn)
    _seed_read_and_xss_sink(conn, read_file="reader.js", xss_sink_file="other.js")
    assert synthesize_stored_xss_flows(conn) == 0


def test_idempotent_does_not_duplicate_on_rerun(tmp_path: Path) -> None:
    conn = _conn(tmp_path)
    _seed_storage_taint_and_write(conn)
    _seed_read_and_xss_sink(conn)
    assert synthesize_stored_xss_flows(conn) == 1
    assert synthesize_stored_xss_flows(conn) == 0
    rows = conn.execute(
        "SELECT COUNT(*) FROM flows WHERE engine = ?", [SYNTHETIC_ENGINE]
    ).fetchone()
    assert rows is not None
    assert rows[0] == 1


def test_no_flow_when_storage_is_not_tainted(tmp_path: Path) -> None:
    """A storage_id without a corresponding storage_taint row is clean —
    the detector must not emit anything even if XSS sinks live next door."""
    conn = _conn(tmp_path)
    _seed_read_and_xss_sink(conn)  # XSS sink exists
    # No storage_taint row -> nothing to derive.
    assert synthesize_stored_xss_flows(conn) == 0


def test_no_flow_when_storage_reads_missing(tmp_path: Path) -> None:
    conn = _conn(tmp_path)
    _seed_storage_taint_and_write(conn)
    # No storage_reads row -> the storage may be tainted but it is never read,
    # so a stored XSS cannot fire.
    assert synthesize_stored_xss_flows(conn) == 0


def test_empty_when_schema_tables_missing(tmp_path: Path) -> None:
    """Defensive — running on a bare DuckDB before apply_schema is a no-op."""
    conn = duckdb.connect(str(tmp_path / "bare.duckdb"))
    assert synthesize_stored_xss_flows(conn) == 0
