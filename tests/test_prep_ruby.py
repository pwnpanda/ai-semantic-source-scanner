"""End-to-end smoke test: prep on the tiny-sinatra Ruby fixture.

Engine is ``none`` so the test doesn't depend on the CodeQL Ruby pack
being downloaded; we only validate that detection, AST extraction
(tree-sitter-ruby), and ingestion correctly route a Ruby project
through the pipeline — including that ``get '/u' do ... end``
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
def test_prep_on_tiny_sinatra_indexes_ruby_symbols(tmp_path: Path, fixtures_dir: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    snap, db_path = run_prep(
        fixtures_dir / "tiny-sinatra",
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    assert snap.snapshot_dir.is_dir()
    assert db_path.is_file()

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        files = conn.execute("SELECT path FROM files WHERE path LIKE '%app.rb'").fetchall()
        assert files, "tiny-sinatra app.rb was not ingested"

        execute_xrefs = conn.execute(
            "SELECT line FROM xrefs WHERE file LIKE '%app.rb' "
            "AND kind = 'call' AND line BETWEEN 14 AND 18"
        ).fetchall()
        assert execute_xrefs, "expected an xref near DB.execute(sql)"

        entrypoints = conn.execute(
            "SELECT kind, signature FROM entrypoints WHERE file LIKE '%app.rb'"
        ).fetchall()
        kinds = {row[0] for row in entrypoints}
        assert "http_route" in kinds, (
            f"expected http_route entrypoint for Sinatra get '/u' do, got {entrypoints!r}"
        )
    finally:
        conn.close()
