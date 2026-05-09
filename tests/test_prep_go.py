"""End-to-end smoke test: prep on the tiny-gin Go fixture.

Engine is ``none`` so the test doesn't depend on the CodeQL Go pack
or the ``go`` toolchain being installed; we only validate that
detection, AST extraction (tree-sitter-go), and ingestion correctly
route a Go project through the pipeline — including that
``r.GET("/u", ...)`` surfaces as an ``http_route`` entrypoint.
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
def test_prep_on_tiny_gin_indexes_go_symbols(tmp_path: Path, fixtures_dir: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    snap, db_path = run_prep(
        fixtures_dir / "tiny-gin",
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    assert snap.snapshot_dir.is_dir()
    assert db_path.is_file()

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        files = conn.execute("SELECT path FROM files WHERE path LIKE '%main.go'").fetchall()
        assert files, "tiny-gin main.go was not ingested"

        symbols = conn.execute(
            "SELECT display_name, kind FROM symbols WHERE file LIKE '%main.go'"
        ).fetchall()
        symbol_names = {row[0] for row in symbols}
        assert "main" in symbol_names

        query_xrefs = conn.execute(
            "SELECT line FROM xrefs WHERE file LIKE '%main.go' "
            "AND kind = 'call' AND line BETWEEN 27 AND 31"
        ).fetchall()
        assert query_xrefs, "expected an xref near db.Query(query)"

        entrypoints = conn.execute(
            "SELECT kind, signature FROM entrypoints WHERE file LIKE '%main.go'"
        ).fetchall()
        kinds = {row[0] for row in entrypoints}
        assert "http_route" in kinds, (
            f"expected http_route entrypoint for r.GET, got {entrypoints!r}"
        )
    finally:
        conn.close()
