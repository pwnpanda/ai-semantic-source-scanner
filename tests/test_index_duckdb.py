"""Tests for ai_codescan.index.duckdb_schema and ingestion."""

from pathlib import Path

import duckdb

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
