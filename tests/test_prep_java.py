"""End-to-end smoke test: prep on the tiny-spring Java fixture.

Engine is ``none`` so the test doesn't depend on the CodeQL Java pack
being downloaded; we only validate that detection, AST extraction
(tree-sitter-java), and ingestion correctly route a Java project
through the pipeline — including that ``@RestController`` /
``@GetMapping`` annotations are surfaced as ``http_route`` entrypoints.
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
def test_prep_on_tiny_spring_indexes_java_symbols(tmp_path: Path, fixtures_dir: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    snap, db_path = run_prep(
        fixtures_dir / "tiny-spring",
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
            "SELECT path FROM files WHERE path LIKE '%UserController.java'"
        ).fetchall()
        assert files, "tiny-spring UserController.java was not ingested"

        symbols = conn.execute(
            "SELECT display_name, kind FROM symbols WHERE file LIKE '%UserController.java'"
        ).fetchall()
        symbol_names = {row[0] for row in symbols}
        assert "UserController" in symbol_names
        assert "getUser" in symbol_names

        execute_xrefs = conn.execute(
            "SELECT line FROM xrefs WHERE file LIKE '%UserController.java' "
            "AND kind = 'call' AND line BETWEEN 30 AND 35"
        ).fetchall()
        assert execute_xrefs, "expected an xref near stmt.executeQuery(sql)"

        entrypoints = conn.execute(
            "SELECT kind, signature FROM entrypoints WHERE file LIKE '%UserController.java'"
        ).fetchall()
        kinds = {row[0] for row in entrypoints}
        assert "http_route" in kinds, (
            f"expected http_route entrypoint for @RestController / @GetMapping, got {entrypoints!r}"
        )
    finally:
        conn.close()
