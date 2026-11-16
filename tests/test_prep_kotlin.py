"""End-to-end smoke test: prep on the tiny-ktor Kotlin fixture.

The ``none`` engine does not use CodeQL. CodeQL ``--build-mode=none`` does not extract Kotlin-only
projects. This test validates detection, syntax tree extraction, and ingestion for a Kotlin
project. It also validates that ``get("/u")`` produces an ``http_route`` entry point.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

import duckdb
import pytest

from ai_codescan import prep as prep_mod
from ai_codescan.prep import run_prep
from ai_codescan.stack_detect import Project, ProjectKind


def _has_node() -> bool:
    return shutil.which("node") is not None


@pytest.mark.skipif(not _has_node(), reason="node runtime required for AST extraction")
def test_prep_on_tiny_ktor_indexes_kotlin_symbols(tmp_path: Path, fixtures_dir: Path) -> None:
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
        files = conn.execute("SELECT path FROM files WHERE path LIKE '%App.kt'").fetchall()
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


def test_codeql_skips_kotlin_only_projects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    project = Project(
        name="mobile-android",
        kind=ProjectKind.JAVA,
        base_path=Path("mobile/android"),
        languages={"kotlin"},
    )

    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Kotlin-only projects must not invoke CodeQL in build mode none")

    monkeypatch.setattr(prep_mod.shutil, "which", lambda _tool: "/usr/bin/codeql")
    monkeypatch.setattr(prep_mod, "_run_codeql_project", fail_if_called)

    with caplog.at_level(logging.INFO):
        had_failures = prep_mod._run_codeql_for_projects(
            tmp_path / "snapshot",
            [project],
            tmp_path / "repo",
            [],
            object(),
            strict=True,
        )

    assert had_failures is False
    assert "--build-mode=none does not extract Kotlin-only projects" in caplog.text
