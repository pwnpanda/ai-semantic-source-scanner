"""End-to-end smoke test: prep on the tiny-aspnet C# fixture.

Engine is ``none`` so the test doesn't depend on the CodeQL C# pack
being downloaded; we only validate that detection, AST extraction
(tree-sitter-c-sharp), and ingestion correctly route a C# project
through the pipeline — including that ``app.MapGet("/u", ...)``
surfaces as an ``http_route`` entrypoint.
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
def test_prep_on_tiny_aspnet_indexes_csharp_symbols(tmp_path: Path, fixtures_dir: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    snap, db_path = run_prep(
        fixtures_dir / "tiny-aspnet",
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    assert snap.snapshot_dir.is_dir()
    assert db_path.is_file()

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        files = conn.execute("SELECT path FROM files WHERE path LIKE '%Program.cs'").fetchall()
        assert files, "tiny-aspnet Program.cs was not ingested"

        execute_xrefs = conn.execute(
            "SELECT line FROM xrefs WHERE file LIKE '%Program.cs' "
            "AND kind = 'call' AND line BETWEEN 19 AND 21"
        ).fetchall()
        assert execute_xrefs, "expected an xref near cmd.ExecuteReader()"

        entrypoints = conn.execute(
            "SELECT kind, signature FROM entrypoints WHERE file LIKE '%Program.cs'"
        ).fetchall()
        kinds = {row[0] for row in entrypoints}
        assert "http_route" in kinds, (
            f"expected http_route entrypoint for app.MapGet, got {entrypoints!r}"
        )
    finally:
        conn.close()
