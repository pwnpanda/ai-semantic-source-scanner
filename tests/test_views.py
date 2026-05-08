"""Tests for ai_codescan.views."""

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.views import render_file_view


def test_render_view_includes_annotations(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    file_abs = (tmp_path / "h.ts").as_posix()
    (tmp_path / "h.ts").write_text(
        "export const h = (req, res) => {\n  const id = req.query.id;\n  res.send(id);\n};\n"
    )
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [file_abs])
    conn.execute(
        "INSERT INTO symbols VALUES ('S1', 'sym', 'function', ?, 1, 4, NULL, 'h')",
        [file_abs],
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', 'S1', 'http.query', 'id', ?)",
        [f"{file_abs}:2"],
    )

    md = render_file_view(conn, file=file_abs)
    assert "# View:" in md
    assert "```typescript" in md or "```ts" in md
    assert "T1" in md
    assert "h.ts" in md


def test_render_view_for_unknown_file_returns_marker(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    md = render_file_view(conn, file=str(tmp_path / "missing.ts"))
    assert "No data for" in md
