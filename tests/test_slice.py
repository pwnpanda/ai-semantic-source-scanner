"""Tests for ai_codescan.slice."""

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.slice import SliceBundle, extract_slice


def _seed(conn: duckdb.DuckDBPyConnection, file: Path) -> None:
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [file.as_posix()])
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', NULL, 'http.body', 'name', ?)",
        [f"{file.as_posix()}:2"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES "
        "('K1', NULL, 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    steps = f'[["{file.as_posix()}", 2, 2], ["{file.as_posix()}", 5, 5]]'
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif', 'definite')",
        [steps],
    )


def test_extract_slice_returns_source_sink_with_context(tmp_path: Path) -> None:
    src = tmp_path / "x.ts"
    src.write_text(
        "// 1\nconst id = req.body.name\n// 3\n// 4\nawait db.query(`x ${id}`)\n// 6\n"
    )
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn, src)

    bundle = extract_slice(conn, flow_id="F1", context_lines=2)

    assert isinstance(bundle, SliceBundle)
    assert bundle.cwe == "CWE-89"
    assert any(step.line == 2 for step in bundle.steps)
    assert any(step.line == 5 for step in bundle.steps)
    src_step = next(s for s in bundle.steps if s.line == 2)
    assert "const id = req.body.name" in src_step.code_excerpt
    assert src_step.context_start == 1
    assert src_step.context_end == 4


def test_extract_slice_unknown_flow_returns_none(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    assert extract_slice(conn, flow_id="missing", context_lines=2) is None
