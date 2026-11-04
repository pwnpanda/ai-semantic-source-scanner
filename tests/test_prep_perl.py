"""End-to-end smoke test: prep on the tiny-mojo Perl fixture.

Engine is ``none``. Validates that a cpanfile-based Perl distribution is
detected, that the PPI worker indexes subs and call xrefs, and that the
Mojolicious route DSL surfaces as an HTTP entrypoint.

Perl is the one supported language with no Joern / Semgrep-native / CodeQL
frontend, so the PPI AST worker plus these entrypoint markers are what the
nominator and the LLM review layer have to work from.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from ai_codescan.ast.runner import perl_worker_available
from ai_codescan.prep import run_prep

pytestmark = pytest.mark.skipif(
    not perl_worker_available(),
    reason="perl + PPI required for Perl AST extraction",
)


def test_prep_on_tiny_mojo_indexes_perl_symbols(tmp_path: Path, fixtures_dir: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    snap, db_path = run_prep(
        fixtures_dir / "tiny-mojo",
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    assert snap.snapshot_dir.is_dir()
    assert db_path.is_file()

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        files = conn.execute("SELECT path FROM files WHERE path LIKE '%app.pl'").fetchall()
        assert files, "tiny-mojo app.pl was not ingested"

        symbols = conn.execute(
            "SELECT display_name FROM symbols WHERE file LIKE '%app.pl'"
        ).fetchall()
        assert "lookup_user" in {row[0] for row in symbols}

        # The Mojolicious ``get '/user' => sub {...}`` DSL is a parenless
        # call; it must still register as an HTTP entrypoint.
        entrypoints = conn.execute(
            "SELECT kind FROM entrypoints WHERE file LIKE '%app.pl'"
        ).fetchall()
        kinds = {row[0] for row in entrypoints}
        assert "http_route" in kinds, (
            f"expected an http_route entrypoint for the Mojolicious route, got {entrypoints!r}"
        )
    finally:
        conn.close()
