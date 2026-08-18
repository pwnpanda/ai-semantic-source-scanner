"""End-to-end smoke test: prep on the tiny-slim PHP fixture.

Engine is ``none`` so the test doesn't require any external SAST tooling
(CodeQL doesn't officially support PHP, so the scanner relies on Semgrep
and Joern when those are available). We only validate that detection,
AST extraction (tree-sitter-php), and ingestion correctly route a PHP
project through the pipeline — including that ``$app->get('/u', ...)``
surfaces as an ``http_route`` entrypoint.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import duckdb
import pytest

from ai_codescan.prep import _files_for_project, run_prep
from ai_codescan.stack_detect import Project, ProjectKind


def _has_node() -> bool:
    return shutil.which("node") is not None


def test_php_file_collection_skips_dependencies_and_wordpress_content(tmp_path: Path) -> None:
    app = tmp_path / "index.php"
    app.write_text("<?php echo 'app';\n", encoding="utf-8")
    for ignored in ("vendor/package", "wp-content/uploads", "wp-content/cache"):
        directory = tmp_path / ignored
        directory.mkdir(parents=True)
        (directory / "ignored.php").write_text("<?php echo 'ignored';\n", encoding="utf-8")
    project = Project(
        name="wordpress",
        kind=ProjectKind.PHP,
        base_path=Path("."),
        languages={"php"},
    )

    _ts, _html, _py, _java, _go, _ruby, php, _cs, _kt, _bash, _yaml = _files_for_project(
        tmp_path,
        project,
    )

    assert php == [app]


@pytest.mark.skipif(not _has_node(), reason="node runtime required for AST extraction")
def test_prep_on_tiny_slim_indexes_php_symbols(tmp_path: Path, fixtures_dir: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    snap, db_path = run_prep(
        fixtures_dir / "tiny-slim",
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    assert snap.snapshot_dir.is_dir()
    assert db_path.is_file()

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        files = conn.execute("SELECT path FROM files WHERE path LIKE '%index.php'").fetchall()
        assert files, "tiny-slim index.php was not ingested"

        query_xrefs = conn.execute(
            "SELECT line FROM xrefs WHERE file LIKE '%index.php' "
            "AND kind = 'call' AND line BETWEEN 23 AND 27"
        ).fetchall()
        assert query_xrefs, "expected an xref near $pdo->query($sql)"

        entrypoints = conn.execute(
            "SELECT kind, signature FROM entrypoints WHERE file LIKE '%index.php'"
        ).fetchall()
        kinds = {row[0] for row in entrypoints}
        assert "http_route" in kinds, (
            f"expected http_route entrypoint for $app->get, got {entrypoints!r}"
        )
    finally:
        conn.close()
