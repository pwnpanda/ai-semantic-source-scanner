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

    md = render_file_view(conn, file=file_abs, source_root=tmp_path)
    assert "# View:" in md
    assert "```typescript" in md or "```ts" in md
    assert "T1" in md
    assert "h.ts" in md


def test_render_view_python_uses_hash_comment_marker(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    file_abs = (tmp_path / "h.py").as_posix()
    (tmp_path / "h.py").write_text(
        "def h(req):\n    user_id = req.args.get('id')\n    return user_id\n"
    )
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'python', 'p', 100)", [file_abs])
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', NULL, 'http.query', 'id', ?)",
        [f"{file_abs}:2"],
    )

    md = render_file_view(conn, file=file_abs, source_root=tmp_path)
    assert "```python" in md
    assert "# [T1] SOURCE" in md  # Python uses # for comments, not //
    assert "// [T1] SOURCE" not in md


def test_render_view_for_unknown_file_returns_marker(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    md = render_file_view(
        conn,
        file=str(tmp_path / "missing.ts"),
        source_root=tmp_path,
    )
    assert "No data for" in md


def test_render_view_rejects_indexed_file_outside_snapshot(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("outside view sentinel\n", encoding="utf-8")
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    conn.execute(
        "INSERT INTO files VALUES (?, 'sha', 'python', 'p', 20)",
        [outside.as_posix()],
    )

    rendered = render_file_view(
        conn,
        file=outside.as_posix(),
        source_root=source_root,
    )

    assert "outside view sentinel" not in rendered
    assert "outside source snapshot" in rendered
