"""End-to-end smoke test: prep on the tiny-bash shell-script fixture.

Engine is ``none``. We validate that bare shell scripts are detected
(via the manifest-less BASH fallback), run through tree-sitter-bash for
symbol/xref extraction, and that a recognisable shell entrypoint marker
(``eval`` in this case) surfaces in the entrypoints table.
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
def test_prep_on_tiny_bash_indexes_shell_symbols(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    snap, db_path = run_prep(
        fixtures_dir / "tiny-bash",
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
            "SELECT path FROM files WHERE path LIKE '%lookup.sh'"
        ).fetchall()
        assert files, "tiny-bash lookup.sh was not ingested"

        symbols = conn.execute(
            "SELECT display_name FROM symbols WHERE file LIKE '%lookup.sh'"
        ).fetchall()
        symbol_names = {row[0] for row in symbols}
        assert "main" in symbol_names

        # The deliberate ``eval`` line should produce an xref and a CLI
        # entrypoint marker.
        entrypoints = conn.execute(
            "SELECT kind FROM entrypoints WHERE file LIKE '%lookup.sh'"
        ).fetchall()
        kinds = {row[0] for row in entrypoints}
        assert "cli" in kinds, (
            f"expected a cli-kind entrypoint for the eval call, got {entrypoints!r}"
        )
    finally:
        conn.close()
