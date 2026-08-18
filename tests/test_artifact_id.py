"""Regression tests for filesystem-safe per-project artifact identifiers."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb

from ai_codescan.artifact_id import (
    is_safe_artifact_id,
    normalize_artifact_id,
    project_artifact_id,
)
from ai_codescan.cli import _hybrid_project_roots
from ai_codescan.engines import codeql, joern, semgrep
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.index.scip import build_scip_index
from ai_codescan.prep import _index_projects
from ai_codescan.stack_detect import Project, ProjectKind
from ai_codescan.third_party import scip_pb2


def _assert_inside(path: Path, root: Path) -> None:
    assert path.resolve().is_relative_to(root.resolve())


def test_project_artifact_id_is_readable_deterministic_and_strict() -> None:
    artifact_id = project_artifact_id("@scope/name", Path("packages/api"))

    assert artifact_id.startswith("scope-name-packages-api-")
    assert is_safe_artifact_id(artifact_id)
    assert project_artifact_id("@scope/name", Path("packages/api")) == artifact_id
    assert normalize_artifact_id(artifact_id) == artifact_id


def test_project_artifact_id_contains_traversal_and_controls_slug_collisions() -> None:
    traversal_id = project_artifact_id("../../escape", Path("../outside"))
    slash_id = project_artifact_id("a/b", Path("."))
    dash_id = project_artifact_id("a-b", Path("."))

    assert is_safe_artifact_id(traversal_id)
    assert "/" not in traversal_id and "\\" not in traversal_id and ".." not in traversal_id
    assert slash_id.startswith("a-b-") and dash_id.startswith("a-b-")
    assert slash_id != dash_id
    assert project_artifact_id("same", Path("one")) != project_artifact_id("same", Path("two"))


def test_hybrid_project_ids_use_raw_manifest_name_and_base_path(tmp_path: Path) -> None:
    projects = (("scoped", "@scope/name"), ("escape", "../../escape"))
    for relative_path, project_name in projects:
        project_root = tmp_path / relative_path
        project_root.mkdir()
        (project_root / "package.json").write_text(
            json.dumps({"name": project_name}),
            encoding="utf-8",
        )
        (project_root / "app.js").write_text("const value = 1;\n", encoding="utf-8")

    roots = _hybrid_project_roots(tmp_path)
    artifact_ids = {root.name: artifact_id for root, artifact_id, _language in roots}

    assert artifact_ids == {
        relative_path: project_artifact_id(project_name, Path(relative_path))
        for relative_path, project_name in projects
    }
    assert all(is_safe_artifact_id(artifact_id) for artifact_id in artifact_ids.values())


def test_scip_direct_entrypoint_keeps_traversal_id_inside_cache(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    cache = tmp_path / "cache"
    prebuilt = tmp_path / "prebuilt.scip"
    prebuilt.write_bytes(scip_pb2.Index().SerializeToString())
    monkeypatch.setenv("AI_CODESCAN_SCIP_JAVA_INDEX", str(prebuilt))

    result = build_scip_index(
        project,
        cache_dir=cache,
        project_id="../../escape",
        language="java",
    )

    _assert_inside(result.scip_path, cache / "scip")
    assert result.scip_path.parent == cache / "scip"
    assert result.project_id == normalize_artifact_id("../../escape")
    assert result.scip_path.name == f"{result.project_id}.scip"


def test_codeql_direct_entrypoints_keep_all_paths_inside_cache(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cache = tmp_path / "cache"
    project = tmp_path / "project"
    project.mkdir()
    calls: list[list[str]] = []
    monkeypatch.setattr(codeql, "_ensure_codeql_on_path", lambda: None)
    monkeypatch.setattr(codeql, "ensure_query_pack", lambda _language: None)
    monkeypatch.setattr(
        codeql.subprocess,
        "run",
        lambda argv, **_kwargs: calls.append(argv),
    )

    db_path = codeql.build_database(
        project,
        cache_dir=cache,
        project_id="../../escape",
    )
    result = codeql.run_queries(
        db_path,
        cache_dir=cache,
        project_id="../../escape",
        codeql_tags=["security"],
    )
    suite_path = Path(calls[-1][-1])
    artifact_id = normalize_artifact_id("../../escape")

    for path in (db_path, result.sarif_path, suite_path):
        _assert_inside(path, cache / "codeql")
        assert path.parent == cache / "codeql"
        assert path.name.startswith(f"{artifact_id}.")
    assert result.project_id == artifact_id


def test_semgrep_direct_entrypoint_keeps_temp_and_sarif_inside_cache(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cache = tmp_path / "cache"
    project = tmp_path / "project"
    project.mkdir()
    temporary_paths: list[Path] = []

    class _Completed:
        returncode = 0
        stderr = b""

    def fake_run(argv, **_kwargs):
        output = Path(argv[argv.index("--output") + 1])
        temporary_paths.append(output)
        output.write_text(json.dumps({"runs": []}), encoding="utf-8")
        return _Completed()

    monkeypatch.setattr(semgrep, "is_available", lambda: True)
    monkeypatch.setattr(semgrep.subprocess, "run", fake_run)

    sarif_path = semgrep.run_semgrep(
        project,
        cache_dir=cache,
        project_id="../../escape",
    )

    _assert_inside(sarif_path, cache / "semgrep")
    assert sarif_path.parent == cache / "semgrep"
    assert sarif_path.name == f"{normalize_artifact_id('../../escape')}.sarif"
    assert temporary_paths
    assert all(path.parent == cache / "semgrep" for path in temporary_paths)


def test_joern_direct_entrypoint_keeps_cpg_and_flows_inside_cache(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cache = tmp_path / "cache"
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.js").write_text("const value = 1;\n", encoding="utf-8")
    cpg_paths: list[Path] = []

    def fake_run(argv, **_kwargs):
        if argv[0] == "joern-parse":
            cpg_path = Path(argv[argv.index("-o") + 1])
            cpg_paths.append(cpg_path)
            cpg_path.write_bytes(b"cpg")

    monkeypatch.setattr(joern, "is_available", lambda: True)
    monkeypatch.setattr(joern.subprocess, "run", fake_run)

    flows_path = joern.run_joern(
        project,
        cache_dir=cache,
        project_id="../../escape",
    )

    assert cpg_paths
    artifact_id = normalize_artifact_id("../../escape")
    for path in (*cpg_paths, flows_path):
        _assert_inside(path, cache / "joern")
        assert path.parent == cache / "joern"
        assert path.name.startswith(f"{artifact_id}.")


def test_ast_index_keeps_original_manifest_name_as_database_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "app.js"
    source.write_text("const value = 1;\n", encoding="utf-8")
    project = Project(
        name="../../escape",
        kind=ProjectKind.NODE,
        base_path=Path("."),
        languages={"javascript"},
    )
    monkeypatch.setattr(
        "ai_codescan.prep.run_jobs",
        lambda _jobs: iter([{"type": "file", "file": str(source), "lang": "javascript"}]),
    )
    conn = duckdb.connect(":memory:")
    apply_schema(conn)

    _index_projects(
        conn,
        snapshot_root=tmp_path,
        projects=[project],
        scip_lookup={},
    )

    row = conn.execute("SELECT project_id FROM files").fetchone()
    conn.close()

    assert row == ("../../escape",)
