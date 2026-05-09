"""Tests for ai_codescan.sidecars."""

import json
from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.sidecars import emit_sidecars, sidecar_path_for


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
    conn.execute(
        "INSERT INTO entrypoints VALUES ('S1', 'http_route', 'app.post', ?, 1)",
        [file],
    )


def test_emit_sidecar_per_file_with_records(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    snapshot = tmp_path / "source"
    sidecars = tmp_path / "sidecars"
    snapshot.mkdir()
    file_abs = (snapshot / "src" / "handler.ts").as_posix()
    (snapshot / "src").mkdir()
    (snapshot / "src" / "handler.ts").write_text("export const handler = () => {};\n")
    _seed(conn, file_abs)

    n = emit_sidecars(conn, snapshot_root=snapshot, sidecars_root=sidecars)
    assert n == 1
    sidecar = sidecars / "src" / "handler.ts.enrich.jsonl"
    assert sidecar.is_file()
    # Snapshot stays untouched.
    assert not (snapshot / "src" / "handler.ts.enrich.jsonl").exists()
    records = [json.loads(line) for line in sidecar.read_text().splitlines() if line.strip()]
    kinds = {r["kind"] for r in records}
    assert {"symbol", "source", "sink", "flow", "entrypoint"} <= kinds


def test_emit_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    snapshot = tmp_path / "source"
    sidecars = tmp_path / "sidecars"
    snapshot.mkdir()
    file_abs = (snapshot / "f.ts").as_posix()
    (snapshot / "f.ts").write_text("//\n")
    _seed(conn, file_abs)
    emit_sidecars(conn, snapshot_root=snapshot, sidecars_root=sidecars)
    first = (sidecars / "f.ts.enrich.jsonl").read_text()
    emit_sidecars(conn, snapshot_root=snapshot, sidecars_root=sidecars)
    second = (sidecars / "f.ts.enrich.jsonl").read_text()
    assert first == second


def test_sidecar_path_for_inside_snapshot(tmp_path: Path) -> None:
    snap = tmp_path / "source"
    sidecars = tmp_path / "sidecars"
    p = sidecar_path_for(snap, sidecars, str(snap / "lib" / "x.ts"))
    assert p == sidecars / "lib" / "x.ts.enrich.jsonl"


def test_sidecar_path_for_outside_snapshot_falls_back_to_leaf(tmp_path: Path) -> None:
    snap = tmp_path / "source"
    sidecars = tmp_path / "sidecars"
    p = sidecar_path_for(snap, sidecars, "/elsewhere/y.js")
    assert p == sidecars / "y.js.enrich.jsonl"
