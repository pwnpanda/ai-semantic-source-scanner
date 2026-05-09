"""Tests for ai_codescan.visualize."""

import json
import shutil
from pathlib import Path

import duckdb
import pytest

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.visualize import render, render_flows_dot


def _seed(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', NULL, 'http.body', 'name', '/abs/x.ts:13')"
    )
    conn.execute("INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'pg', 'concat', '[]')")
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif', 'definite')",
        [json.dumps([["/abs/x.ts", 13], ["/abs/x.ts", 42]])],
    )


def test_render_flows_dot_includes_source_and_sink(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "x.duckdb"))
    apply_schema(conn)
    _seed(conn)
    dot = render_flows_dot(conn)
    assert dot.startswith("digraph flows {")
    assert "/abs/x.ts:13" in dot
    assert "sql.exec" in dot
    assert "->" in dot


def test_render_dot_writes_file(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "y.duckdb"))
    apply_schema(conn)
    _seed(conn)
    out = tmp_path / "out.dot"
    render(conn, out_path=out, fmt="dot")
    assert out.is_file()
    assert "digraph" in out.read_text()


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("dot") is None, reason="graphviz dot not installed")
def test_render_svg_via_dot(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "z.duckdb"))
    apply_schema(conn)
    _seed(conn)
    out = tmp_path / "out.svg"
    render(conn, out_path=out, fmt="svg")
    assert out.is_file()
    body = out.read_text(encoding="utf-8")
    assert "<svg" in body
