"""Tests for ai_codescan.index.duckdb_schema and ingestion."""

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_ingest import ingest
from ai_codescan.index.duckdb_schema import apply_schema


def test_apply_schema_creates_phase1_tables(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    tables = {row[0] for row in conn.execute("SHOW TABLES").fetchall()}
    assert {
        "files",
        "symbols",
        "xrefs",
        "taint_sources",
        "taint_sinks",
        "flows",
        "notes",
        "entrypoints",
    } <= tables


def test_apply_schema_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    apply_schema(conn)  # second call must not raise
    row = conn.execute("SELECT COUNT(*) FROM files").fetchone()
    assert row is not None
    assert row[0] == 0


def test_views_for_source_sink_navigation(tmp_path: Path) -> None:
    db = tmp_path / "z.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    views = {
        row[0]
        for row in conn.execute(
            "SELECT view_name FROM duckdb_views() WHERE schema_name='main'"
        ).fetchall()
    }
    assert {"v_sources_to_sinks", "v_sinks_from_sources"} <= views


def test_ingest_files_and_symbols(tmp_path: Path) -> None:
    db = tmp_path / "ing.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)

    file_records = [{"file": "/abs/x.ts", "lang": "ts", "lineCount": 10}]
    symbol_records = [
        {
            "type": "symbol",
            "file": "/abs/x.ts",
            "kind": "function",
            "name": "greet",
            "range": [1, 3],
            "syntheticId": "synthetic:abc123",
        }
    ]
    xref_records = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/x.ts",
            "line": 5,
            "callerSyntheticId": None,
            "calleeText": "greet",
        }
    ]
    ingest(
        conn,
        files=file_records,
        symbols=symbol_records,
        xrefs=xref_records,
        scip_lookup={},
        project_id="p",
        snapshot_root=Path("/abs"),
    )
    rows = conn.execute("SELECT id, kind, display_name FROM symbols").fetchall()
    assert ("synthetic:abc123", "function", "greet") in rows
    xref_rows = conn.execute("SELECT kind, file, line FROM xrefs").fetchall()
    assert ("call", "/abs/x.ts", 5) in xref_rows


def test_ingest_prefers_scip_symbol_over_synthetic(tmp_path: Path) -> None:
    db = tmp_path / "ing2.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)

    file_records = [{"file": "/abs/x.ts", "lang": "ts", "lineCount": 10}]
    symbol_records = [
        {
            "type": "symbol",
            "file": "/abs/x.ts",
            "kind": "function",
            "name": "greet",
            "range": [1, 3],
            "syntheticId": "synthetic:abc123",
        }
    ]
    scip_lookup = {("/abs/x.ts", 1, 3): "scip:npm/@p/0.0.1/x.ts/greet#"}
    ingest(
        conn,
        files=file_records,
        symbols=symbol_records,
        xrefs=[],
        scip_lookup=scip_lookup,
        project_id="p",
        snapshot_root=Path("/abs"),
    )
    rows = conn.execute("SELECT id, sym FROM symbols").fetchall()
    assert ("scip:npm/@p/0.0.1/x.ts/greet#", "scip:npm/@p/0.0.1/x.ts/greet#") in rows
