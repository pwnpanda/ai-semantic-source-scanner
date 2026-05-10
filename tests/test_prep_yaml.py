"""End-to-end smoke test: prep on the tiny-actions GitHub Actions fixture.

Engine is ``none``. We validate that a workflow-only repo is detected
as a YAML project, run through tree-sitter-yaml for symbol/xref
extraction, and that the workflow trigger surfaces as an
``http_route`` entrypoint while attacker-controllable
``${{ github.event.* }}`` interpolations surface as ``cli`` markers.
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
def test_prep_on_tiny_actions_indexes_workflow(tmp_path: Path, fixtures_dir: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    snap, db_path = run_prep(
        fixtures_dir / "tiny-actions",
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    assert snap.snapshot_dir.is_dir()
    assert db_path.is_file()

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        files = conn.execute("SELECT path FROM files WHERE path LIKE '%triage.yml'").fetchall()
        assert files, "tiny-actions triage.yml was not ingested"

        entrypoints = conn.execute(
            "SELECT kind, signature FROM entrypoints WHERE file LIKE '%triage.yml'"
        ).fetchall()
        kinds = {row[0] for row in entrypoints}
        # ``on:`` workflow trigger surfaces as a route entrypoint.
        assert "http_route" in kinds, f"expected http_route for ``on: issues``, got {entrypoints!r}"
        # The attacker-controllable ``${{ github.event.issue.title }}``
        # template expression surfaces as a CLI marker.
        assert "cli" in kinds, (
            f"expected cli marker for github.event template expr, got {entrypoints!r}"
        )
    finally:
        conn.close()
