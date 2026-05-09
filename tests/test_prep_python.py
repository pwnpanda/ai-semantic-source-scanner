"""End-to-end smoke test: prep on the tiny-flask Python fixture.

Engine is ``none`` so the test doesn't depend on the CodeQL Python pack
being downloaded; we only validate that detection, AST, and ingestion
correctly route a Python project through the pipeline.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import duckdb
import pytest

from ai_codescan.prep import run_prep


def _has_node() -> bool:
    return shutil.which("node") is not None


@pytest.mark.skipif(not _has_node(), reason="node runtime required for AST extraction")
def test_prep_on_tiny_flask_indexes_python_symbols(tmp_path: Path, fixtures_dir: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    snap, db_path = run_prep(
        fixtures_dir / "tiny-flask",
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    assert snap.snapshot_dir.is_dir()
    assert db_path.is_file()

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        files = conn.execute("SELECT path FROM files WHERE path LIKE '%app.py'").fetchall()
        assert files, "tiny-flask app.py was not ingested"

        symbols = conn.execute(
            "SELECT display_name, kind FROM symbols WHERE file LIKE '%app.py'"
        ).fetchall()
        symbol_names = {row[0] for row in symbols}
        assert "_db" in symbol_names
        assert "get_user" in symbol_names

        # The xref to cur.execute(sql) should be picked up by the Python AST worker.
        execute_calls = conn.execute(
            "SELECT line FROM xrefs WHERE file LIKE '%app.py' AND kind = 'call' "
            "AND line >= 25 AND line <= 28"
        ).fetchall()
        assert execute_calls, "expected an xref near the cursor.execute call site"
    finally:
        conn.close()
