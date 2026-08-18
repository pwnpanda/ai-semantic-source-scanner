"""Tests for ai_codescan.index.duckdb_schema and ingestion."""

from pathlib import Path

import duckdb
import pytest

from ai_codescan.index.duckdb_ingest import ingest
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.source_paths import SourcePathError


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
        "candidate_scores",
        "review_verdicts",
        "notes",
        "entrypoints",
    } <= tables
    score_columns = {
        row[1] for row in conn.execute("PRAGMA table_info('candidate_scores')").fetchall()
    }
    assert "processing_bucket" in score_columns


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
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "x.ts"
    source.write_text("\n" * 10, encoding="utf-8")

    file_records = [{"file": source.as_posix(), "lang": "ts", "lineCount": 10}]
    symbol_records = [
        {
            "type": "symbol",
            "file": source.as_posix(),
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
            "file": source.as_posix(),
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
        snapshot_root=source_root,
    )
    rows = conn.execute("SELECT id, kind, display_name FROM symbols").fetchall()
    assert ("synthetic:abc123", "function", "greet") in rows
    xref_rows = conn.execute("SELECT kind, file, line FROM xrefs").fetchall()
    assert ("call", source.as_posix(), 5) in xref_rows


def test_ingest_prefers_scip_symbol_over_synthetic(tmp_path: Path) -> None:
    db = tmp_path / "ing2.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "x.ts"
    source.write_text("\n" * 10, encoding="utf-8")

    file_records = [{"file": source.as_posix(), "lang": "ts", "lineCount": 10}]
    symbol_records = [
        {
            "type": "symbol",
            "file": source.as_posix(),
            "kind": "function",
            "name": "greet",
            "range": [1, 3],
            "syntheticId": "synthetic:abc123",
        }
    ]
    scip_lookup = {(source.as_posix(), 1, 3): "scip:npm/@p/0.0.1/x.ts/greet#"}
    ingest(
        conn,
        files=file_records,
        symbols=symbol_records,
        xrefs=[],
        scip_lookup=scip_lookup,
        project_id="p",
        snapshot_root=source_root,
    )
    rows = conn.execute("SELECT id, sym FROM symbols").fetchall()
    assert ("scip:npm/@p/0.0.1/x.ts/greet#", "scip:npm/@p/0.0.1/x.ts/greet#") in rows


def test_ingest_validates_all_ast_paths_before_inserting(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    valid = source_root / "valid.ts"
    valid.write_text("export const valid = true;\n", encoding="utf-8")
    outside = tmp_path / "outside.ts"
    outside.write_text("outside AST sentinel\n", encoding="utf-8")
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    with pytest.raises(SourcePathError, match="escapes snapshot"):
        ingest(
            conn,
            files=[{"file": valid.as_posix(), "lang": "ts", "lineCount": 1}],
            symbols=[
                {
                    "type": "symbol",
                    "file": outside.as_posix(),
                    "kind": "function",
                    "name": "poisoned",
                    "range": [1, 1],
                    "syntheticId": "synthetic:poisoned",
                }
            ],
            xrefs=[],
            scip_lookup={},
            project_id="p",
            snapshot_root=source_root,
        )

    assert conn.execute("SELECT COUNT(*) FROM files").fetchone() == (0,)
