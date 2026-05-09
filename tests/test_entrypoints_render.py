"""Tests for entrypoint ingestion + rendering."""

from pathlib import Path

import duckdb

from ai_codescan.entrypoints.detectors import Entrypoint
from ai_codescan.entrypoints.ingest import ingest_entrypoints
from ai_codescan.entrypoints.render import render_entrypoints_md
from ai_codescan.index.duckdb_schema import apply_schema


def test_ingest_writes_rows(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    eps = [
        Entrypoint(symbol_id=None, kind="http_route", signature="app.get", file="/a.js", line=5),
        Entrypoint(symbol_id=None, kind="listener", signature="bus.on", file="/b.ts", line=9),
    ]
    ingest_entrypoints(conn, eps)
    rows = conn.execute(
        "SELECT kind, signature, file, line FROM entrypoints ORDER BY kind"
    ).fetchall()
    assert rows == [
        ("http_route", "app.get", "/a.js", 5),
        ("listener", "bus.on", "/b.ts", 9),
    ]


def test_render_includes_file_and_line() -> None:
    eps = [
        Entrypoint(
            symbol_id=None, kind="http_route", signature="app.get", file="/srv/app.js", line=42
        ),
    ]
    md = render_entrypoints_md(target_name="t", entrypoints=eps)
    assert "/srv/app.js:42" in md


def test_render_groups_by_kind() -> None:
    eps = [
        Entrypoint(symbol_id=None, kind="http_route", signature="app.get", file="/a.js", line=5),
        Entrypoint(symbol_id=None, kind="http_route", signature="app.post", file="/a.js", line=7),
        Entrypoint(symbol_id=None, kind="listener", signature="bus.on", file="/b.ts", line=9),
    ]
    md = render_entrypoints_md(target_name="t", entrypoints=eps)
    assert "# Entrypoints: t" in md
    assert "## http_route" in md and "## listener" in md
    http_idx = md.index("## http_route")
    listener_idx = md.index("## listener")
    assert http_idx < listener_idx


def test_render_handles_empty() -> None:
    md = render_entrypoints_md(target_name="t", entrypoints=[])
    assert "No entrypoints detected" in md
