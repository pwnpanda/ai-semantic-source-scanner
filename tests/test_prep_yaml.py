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
from ai_codescan.sidecars import sidecar_path_for


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


@pytest.mark.skipif(not _has_node(), reason="node runtime required for AST extraction")
def test_prep_indexes_polyglot_yaml_once_and_skips_build_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "polyglot"
    (target / "src" / "main" / "kotlin").mkdir(parents=True)
    (target / "src" / "main" / "resources").mkdir(parents=True)
    (target / "build").mkdir()
    (target / "package.json").write_text('{"name":"frontend"}\n', encoding="utf-8")
    (target / "build.gradle.kts").write_text('plugins { kotlin("jvm") }\n', encoding="utf-8")
    (target / "src" / "main" / "kotlin" / "App.kt").write_text(
        "fun main() = Unit\n",
        encoding="utf-8",
    )
    config = target / "src" / "main" / "resources" / "application.yml"
    config.write_text("on: push\n", encoding="utf-8")
    (target / "build" / "generated.yml").write_text("on: pull_request\n", encoding="utf-8")
    monkeypatch.setattr("ai_codescan.prep._build_scip_lookup", lambda *_args: {})

    _snapshot, db_path = run_prep(
        target,
        cache_root=tmp_path / "cache",
        engine="none",
        bug_classes=[],
        quiet=True,
    )

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        indexed_config = conn.execute(
            "SELECT COUNT(*) FROM files WHERE path LIKE '%application.yml'"
        ).fetchone()
        generated = conn.execute(
            "SELECT COUNT(*) FROM files WHERE path LIKE '%build/generated.yml'"
        ).fetchone()
        entrypoints = conn.execute(
            "SELECT COUNT(*) FROM entrypoints WHERE file LIKE '%application.yml'"
        ).fetchone()
    finally:
        conn.close()

    assert indexed_config == (1,)
    assert generated == (0,)
    assert entrypoints == (1,)


@pytest.mark.skipif(not _has_node(), reason="node runtime required for AST extraction")
def test_prep_rebuild_removes_deleted_source_state_and_sidecar(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "package.json").write_text('{"name":"project"}\n', encoding="utf-8")
    stale_config = target / "application.yml"
    stale_config.write_text("on: push\n", encoding="utf-8")
    cache_root = tmp_path / "cache"

    first_snapshot, db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    repo_dir = db_path.parent
    stale_snapshot_path = first_snapshot.snapshot_dir / "application.yml"
    stale_sidecar = sidecar_path_for(
        first_snapshot.snapshot_dir,
        repo_dir / "sidecars",
        stale_snapshot_path.as_posix(),
    )
    assert stale_sidecar.is_file()

    stale_config.unlink()
    (target / "server.js").write_text("export const healthy = true;\n", encoding="utf-8")
    second_snapshot, db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
        force=True,
    )

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        stale_files = conn.execute(
            "SELECT path FROM files WHERE path LIKE '%application.yml'"
        ).fetchall()
        stale_entrypoints = conn.execute(
            "SELECT file FROM entrypoints WHERE file LIKE '%application.yml'"
        ).fetchall()
    finally:
        conn.close()

    assert second_snapshot.snapshot_dir == first_snapshot.snapshot_dir
    assert stale_files == []
    assert stale_entrypoints == []
    assert not stale_sidecar.exists()
