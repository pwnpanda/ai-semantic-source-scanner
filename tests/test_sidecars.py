"""Tests for ai_codescan.sidecars."""

import json
from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.sidecars import emit_sidecars


def _seed(conn: duckdb.DuckDBPyConnection, file: str) -> None:
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [file])
    conn.execute(
        "INSERT INTO symbols VALUES (?, 'sym1', 'function', ?, 1, 5, NULL, 'handler')",
        ["S1", file],
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', 'S1', 'http.body', 'name', ?)",
        [f"{file}:2"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', 'S1', 'sql.exec', 'pg', 'template-literal', '[]')",
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F1', 'T1', 'K1', 'CWE-89', 'codeql', '[]', '/sarif', 'definite')"
    )
    conn.execute("INSERT INTO entrypoints VALUES ('S1', 'http_route', 'app.post')")


def test_emit_sidecar_per_file_with_records(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    file_abs = (tmp_path / "src" / "handler.ts").as_posix()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "handler.ts").write_text("export const handler = () => {};\n")
    _seed(conn, file_abs)

    n = emit_sidecars(conn, snapshot_root=tmp_path)
    assert n == 1
    sidecar = tmp_path / "src" / "handler.ts.enrich.jsonl"
    assert sidecar.is_file()
    records = [json.loads(line) for line in sidecar.read_text().splitlines() if line.strip()]
    kinds = {r["kind"] for r in records}
    assert {"symbol", "source", "sink", "flow", "entrypoint"} <= kinds


def test_emit_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    file_abs = (tmp_path / "f.ts").as_posix()
    (tmp_path / "f.ts").write_text("//\n")
    _seed(conn, file_abs)
    emit_sidecars(conn, snapshot_root=tmp_path)
    first = (tmp_path / "f.ts.enrich.jsonl").read_text()
    emit_sidecars(conn, snapshot_root=tmp_path)
    second = (tmp_path / "f.ts.enrich.jsonl").read_text()
    assert first == second
