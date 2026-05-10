"""End-to-end smoke test: prep on the tiny-ktor Kotlin fixture.

Engine is ``none`` so the test doesn't depend on the CodeQL Kotlin
extractor (covered by the ``java-kotlin`` extractor when CodeQL runs).
We only validate that detection, AST extraction (tree-sitter-kotlin),
and ingestion correctly route a Kotlin project through the pipeline —
including that ``get("/u")`` surfaces as an ``http_route`` entrypoint.
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
def test_prep_on_tiny_ktor_indexes_kotlin_symbols(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    snap, db_path = run_prep(
        fixtures_dir / "tiny-ktor",
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    assert snap.snapshot_dir.is_dir()
    assert db_path.is_file()

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        files = conn.execute(
            "SELECT path FROM files WHERE path LIKE '%App.kt'"
        ).fetchall()
        assert files, "tiny-ktor App.kt was not ingested"

        symbols = conn.execute(
            "SELECT display_name FROM symbols WHERE file LIKE '%App.kt'"
        ).fetchall()
        symbol_names = {row[0] for row in symbols}
        assert "main" in symbol_names

        sql_xrefs = conn.execute(
            "SELECT line FROM xrefs WHERE file LIKE '%App.kt' "
            "AND kind = 'call' AND line BETWEEN 22 AND 26"
        ).fetchall()
        assert sql_xrefs, "expected an xref near conn.createStatement().executeQuery(sql)"

        entrypoints = conn.execute(
            "SELECT kind, signature FROM entrypoints WHERE file LIKE '%App.kt'"
        ).fetchall()
        kinds = {row[0] for row in entrypoints}
        assert "http_route" in kinds, (
            f"expected http_route entrypoint for Ktor get('/u'), got {entrypoints!r}"
        )
    finally:
        conn.close()
