"""Tests for ai_codescan.engines.hybrid."""

import json
from pathlib import Path

import duckdb
import pytest

from ai_codescan.cache_state import set_scan_stage
from ai_codescan.engines import joern as joern_eng
from ai_codescan.engines import semgrep as semgrep_eng
from ai_codescan.engines.hybrid import (
    HybridStageError,
    _ingest_joern_jsonl,
    dedupe_flows,
    run_hybrid,
)
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.source_paths import SourcePathError


def _seed_two_engine_flows(conn: duckdb.DuckDBPyConnection) -> None:
    same_key = json.dumps([["/abs/x.ts", 13], ["/abs/y.ts", 42]])
    conn.execute(
        "INSERT INTO flows VALUES "
        "('codeql-1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif/c', 'definite')",
        [same_key],
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('semgrep-1', 'T2', 'K2', 'CWE-89', 'semgrep', ?, '/sarif/s', 'inferred')",
        [same_key],
    )
    different_key = json.dumps([["/abs/x.ts", 99], ["/abs/y.ts", 100]])
    conn.execute(
        "INSERT INTO flows VALUES "
        "('codeql-2', 'T3', 'K3', 'CWE-79', 'codeql', ?, '/sarif/c2', 'definite')",
        [different_key],
    )


def test_dedupe_collapses_same_key_keeps_highest_confidence(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_two_engine_flows(conn)

    removed = dedupe_flows(conn)
    assert removed == 1

    rows = conn.execute("SELECT fid, engine, confidence FROM flows ORDER BY fid").fetchall()
    assert ("codeql-1", "codeql+semgrep", "definite") in rows
    assert ("codeql-2", "codeql", "definite") in rows
    fids = {r[0] for r in rows}
    assert "semgrep-1" not in fids


def test_dedupe_boosts_confidence_on_two_engine_consensus(tmp_path: Path) -> None:
    """Two engines on the same flow → survivor's confidence bumps one rank up."""
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    same_key = json.dumps([["/abs/x.ts", 13], ["/abs/y.ts", 42]])
    # Both engines report the flow at 'inferred' — consensus should lift to 'definite'.
    conn.execute(
        "INSERT INTO flows VALUES "
        "('codeql-1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif/c', 'inferred')",
        [same_key],
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('semgrep-1', 'T2', 'K2', 'CWE-89', 'semgrep', ?, '/sarif/s', 'inferred')",
        [same_key],
    )

    removed = dedupe_flows(conn)
    assert removed == 1
    row = conn.execute(
        "SELECT engine, confidence FROM flows WHERE fid IN ('codeql-1','semgrep-1')"
    ).fetchone()
    assert row == ("codeql+semgrep", "definite")


def test_dedupe_three_engine_consensus_forces_definite(tmp_path: Path) -> None:
    """Three engines agreeing → confidence forced to 'definite' regardless of base."""
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    same_key = json.dumps([["/abs/x.ts", 13], ["/abs/y.ts", 42]])
    conn.execute(
        "INSERT INTO flows VALUES "
        "('codeql-1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif/c', 'llm-suggested')",
        [same_key],
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('semgrep-1', 'T2', 'K2', 'CWE-89', 'semgrep', ?, '/sarif/s', 'llm-suggested')",
        [same_key],
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('joern-1', 'T3', 'K3', 'CWE-89', 'joern', ?, '/jsonl/j', 'inferred')",
        [same_key],
    )

    removed = dedupe_flows(conn)
    assert removed == 2
    row = conn.execute(
        "SELECT engine, confidence FROM flows WHERE fid IN ('codeql-1','semgrep-1','joern-1')"
    ).fetchone()
    assert row is not None
    assert row[1] == "definite"
    assert "+" in row[0]
    parts = set(row[0].split("+"))
    assert parts == {"codeql", "semgrep", "joern"}


def test_dedupe_two_engine_boost_caps_at_definite(tmp_path: Path) -> None:
    """A 'definite' survivor + 2 engines should not exceed 'definite'."""
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    same_key = json.dumps([["/abs/x.ts", 13], ["/abs/y.ts", 42]])
    conn.execute(
        "INSERT INTO flows VALUES "
        "('codeql-1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif/c', 'definite')",
        [same_key],
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('semgrep-1', 'T2', 'K2', 'CWE-89', 'semgrep', ?, '/sarif/s', 'inferred')",
        [same_key],
    )
    dedupe_flows(conn)
    row = conn.execute("SELECT confidence FROM flows WHERE fid = 'codeql-1'").fetchone()
    assert row == ("definite",)


def test_dedupe_no_op_when_keys_unique(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute(
        "INSERT INTO flows VALUES ('a', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif', 'definite')",
        [json.dumps([["/x", 1], ["/y", 2]])],
    )
    conn.execute(
        "INSERT INTO flows VALUES ('b', 'T2', 'K2', 'CWE-79', 'codeql', ?, '/sarif', 'definite')",
        [json.dumps([["/x", 3], ["/y", 4]])],
    )
    assert dedupe_flows(conn) == 0


def test_ingest_joern_records_flow_type_co_location_for_fallback(tmp_path: Path) -> None:
    """Recall-First Invariant 6: Joern fallback emissions carry flow_type=co-location
    so the scorer can demote them without dropping the candidate."""
    source = tmp_path / "server.js"
    source.write_text("\n" * 8, encoding="utf-8")
    jsonl = tmp_path / "flows.jsonl"
    jsonl.write_text(
        json.dumps(
            {
                "fid": "joern-colo",
                "source_file": source.as_posix(),
                "source_line": 3,
                "sink_file": source.as_posix(),
                "sink_line": 5,
                "source_name": "req.query.html",
                "sink_name": "send",
                "cwe": "CWE-79",
                "sink_class": "html.write",
                "parameterization": "unknown",
                "flow_type": "co-location",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    inserted = _ingest_joern_jsonl(
        conn,
        jsonl_path=jsonl,
        project_id="x",
        snapshot_root=tmp_path,
    )

    assert inserted == 1
    row = conn.execute("SELECT flow_type FROM flow_metadata").fetchone()
    assert row == ("co-location",)


def test_ingest_joern_defaults_flow_type_to_dataflow(tmp_path: Path) -> None:
    """Records without flow_type default to 'dataflow' (the recall-first default)."""
    x_source = tmp_path / "x.js"
    y_source = tmp_path / "y.js"
    x_source.write_text("source();\n", encoding="utf-8")
    y_source.write_text("sink();\n", encoding="utf-8")
    jsonl = tmp_path / "flows.jsonl"
    jsonl.write_text(
        json.dumps(
            {
                "fid": "joern-df",
                "source_file": x_source.as_posix(),
                "source_line": 1,
                "sink_file": y_source.as_posix(),
                "sink_line": 2,
                "source_name": "req.body",
                "sink_name": "query",
                "cwe": "CWE-89",
                "sink_class": "sql.exec",
                "parameterization": "unknown",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    _ingest_joern_jsonl(conn, jsonl_path=jsonl, project_id="x", snapshot_root=tmp_path)
    row = conn.execute("SELECT flow_type FROM flow_metadata").fetchone()
    assert row == ("dataflow",)


def test_ingest_joern_resolves_relative_paths_from_project_root(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    project_root = source_root / "service"
    project_root.mkdir(parents=True)
    source = project_root / "src.js"
    sink = project_root / "sink.js"
    source.write_text("source();\n", encoding="utf-8")
    sink.write_text("sink();\n", encoding="utf-8")
    jsonl = tmp_path / "flows.jsonl"
    jsonl.write_text(
        json.dumps(
            {
                "fid": "relative",
                "source_file": "src.js",
                "source_line": 1,
                "sink_file": "sink.js",
                "sink_line": 1,
                "source_name": "input",
                "sink_name": "sink",
                "cwe": "CWE-89",
                "sink_class": "sql.exec",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    assert (
        _ingest_joern_jsonl(
            conn,
            jsonl_path=jsonl,
            project_id="service",
            snapshot_root=source_root,
            project_root=project_root,
        )
        == 1
    )
    steps = conn.execute("SELECT steps_json FROM flows").fetchone()
    assert steps is not None
    assert json.loads(steps[0]) == [
        [source.as_posix(), 1, 1],
        [sink.as_posix(), 1, 1],
    ]


def test_ingest_joern_keeps_path_containment_flow_visible(tmp_path: Path) -> None:
    """Recall-First Invariant 2: high-confidence path containment mitigation
    must NOT suppress a CWE-22 flow at ingest. It should surface later as a
    `mitigation_signal` score factor during candidate scoring, but the flow
    record itself stays in the table for review."""
    source = tmp_path / "Program.cs"
    source.write_text(
        "\n".join(
            [
                'var root = Path.GetFullPath("public");',
                "var rootWithSeparator = root + Path.DirectorySeparatorChar;",
                'app.MapGet("/files/{name}", (string name) =>',
                "{",
                "    var requested = Path.GetFullPath(Path.Combine(root, name));",
                "    if (!requested.StartsWith(rootWithSeparator, StringComparison.Ordinal))",
                "    {",
                "        return Results.BadRequest();",
                "    }",
                "    return Results.Text(File.ReadAllText(requested));",
                "});",
            ]
        ),
        encoding="utf-8",
    )
    jsonl = tmp_path / "flows.jsonl"
    jsonl.write_text(
        json.dumps(
            {
                "fid": "joern-path",
                "source_file": source.as_posix(),
                "source_line": 3,
                "sink_file": source.as_posix(),
                "sink_line": 10,
                "source_name": "string name",
                "sink_name": "ReadAllText",
                "cwe": "CWE-22",
                "sink_class": "fs.read",
                "parameterization": "unknown",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    inserted = _ingest_joern_jsonl(
        conn,
        jsonl_path=jsonl,
        project_id="path-contained",
        snapshot_root=tmp_path,
    )

    assert inserted == 1, "flow must remain visible — mitigation belongs in scoring, not ingest"
    row = conn.execute("SELECT cwe, engine FROM flows").fetchone()
    assert row == ("CWE-22", "joern")


@pytest.mark.parametrize("bad_path", ("/etc/passwd", "../outside.js", "linked.js"))
def test_ingest_joern_rejects_paths_outside_snapshot(
    tmp_path: Path,
    bad_path: str,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    valid = source_root / "valid.js"
    valid.write_text("sink();\n", encoding="utf-8")
    outside = tmp_path / "outside.js"
    outside.write_text("outside Joern sentinel\n", encoding="utf-8")
    (source_root / "linked.js").symlink_to(outside)
    jsonl = tmp_path / "flows.jsonl"
    jsonl.write_text(
        json.dumps(
            {
                "source_file": bad_path,
                "source_line": 1,
                "sink_file": valid.as_posix(),
                "sink_line": 1,
                "source_name": "input",
                "sink_name": "sink",
                "cwe": "CWE-89",
                "sink_class": "sql.exec",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    with pytest.raises(SourcePathError, match="escapes snapshot"):
        _ingest_joern_jsonl(
            conn,
            jsonl_path=jsonl,
            project_id="poisoned",
            snapshot_root=source_root,
        )

    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (0,)


def test_ingest_joern_validates_all_paths_before_inserting(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "valid.js"
    source.write_text("source();\nsink();\n", encoding="utf-8")
    base = {
        "source_file": source.as_posix(),
        "source_line": 1,
        "sink_file": source.as_posix(),
        "sink_line": 2,
        "source_name": "input",
        "sink_name": "sink",
        "cwe": "CWE-89",
        "sink_class": "sql.exec",
    }
    jsonl = tmp_path / "flows.jsonl"
    jsonl.write_text(
        json.dumps({**base, "fid": "valid"})
        + "\n"
        + json.dumps({**base, "fid": "poisoned", "source_file": "/etc/passwd"})
        + "\n",
        encoding="utf-8",
    )
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    with pytest.raises(SourcePathError, match="escapes snapshot"):
        _ingest_joern_jsonl(
            conn,
            jsonl_path=jsonl,
            project_id="transactional",
            snapshot_root=source_root,
        )

    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (0,)
    assert conn.execute("SELECT COUNT(*) FROM taint_sources").fetchone() == (0,)


# ---------------------------------------------------------------------------
# Integration: run_hybrid drives both JS and Python projects with mocked engines
# ---------------------------------------------------------------------------


@pytest.fixture
def _stub_engines(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Stub Semgrep + Joern so run_hybrid can be exercised without their CLIs."""

    def fake_run_semgrep(project_root: Path, *, cache_dir: Path, project_id: str, **_kwargs):
        sarif = cache_dir / "semgrep" / f"{project_id}.sarif"
        sarif.parent.mkdir(parents=True, exist_ok=True)
        # An empty SARIF body — ingest_sarif tolerates this and inserts zero flows.
        sarif.write_text(
            json.dumps({"version": "2.1.0", "runs": []}),
            encoding="utf-8",
        )
        return sarif

    captured_languages: list[str] = []

    def fake_run_joern(
        project_root: Path,
        *,
        cache_dir: Path,
        project_id: str,
        language: str = "javascript",
    ):
        captured_languages.append(language)
        (project_root / "x").write_text("source\n", encoding="utf-8")
        (project_root / "y").write_text("sink\n", encoding="utf-8")
        out = cache_dir / "joern" / f"{project_id}.flows.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "fid": f"joern-{project_id}",
            "source_file": f"{project_root.as_posix()}/x",
            "source_line": 1,
            "sink_file": f"{project_root.as_posix()}/y",
            "sink_line": 2,
            "source_name": "src",
            "sink_name": "exec",
            "cwe": "CWE-89",
            "sink_class": "sql.exec",
            "parameterization": "unknown",
        }
        out.write_text(json.dumps(record) + "\n", encoding="utf-8")
        return out

    monkeypatch.setattr(semgrep_eng, "is_available", lambda: True)
    monkeypatch.setattr(semgrep_eng, "run_semgrep", fake_run_semgrep)
    monkeypatch.setattr(joern_eng, "is_available", lambda: True)
    monkeypatch.setattr(joern_eng, "run_joern", fake_run_joern)
    return captured_languages


def test_run_hybrid_routes_kotlin_language_to_joern(
    tmp_path: Path, _stub_engines: list[str]
) -> None:
    """A project_root tuple with language='kotlin' reaches Joern's stub
    with the kotlin token forwarded — exercising the kotlin2cpg dispatch
    path independently of the cli.py file-count heuristic."""
    db_path = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    conn.close()

    snapshot = tmp_path / "snap"
    kt_root = snapshot / "kt-app"
    kt_root.mkdir(parents=True)
    repo_dir = tmp_path / "cache"
    repo_dir.mkdir()

    run_hybrid(
        [(kt_root, "kt-app", "kotlin")],
        snapshot_root=snapshot,
        repo_dir=repo_dir,
        db_path=db_path,
    )
    assert _stub_engines == ["kotlin"]


def test_run_hybrid_routes_per_project_language(tmp_path: Path, _stub_engines: list[str]) -> None:
    """A JS and a Python project route to Joern with the right language flag,
    and each project's flow is ingested under engine='joern'."""
    db_path = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    conn.close()

    snapshot = tmp_path / "snap"
    js_root = snapshot / "js-app"
    py_root = snapshot / "py-app"
    js_root.mkdir(parents=True)
    py_root.mkdir(parents=True)

    project_roots = [
        (js_root, "js-app", "javascript"),
        (py_root, "py-app", "python"),
    ]

    repo_dir = tmp_path / "cache"
    repo_dir.mkdir()
    stats = run_hybrid(
        project_roots,
        snapshot_root=snapshot,
        repo_dir=repo_dir,
        db_path=db_path,
    )

    # Both languages were forwarded to the Joern stub.
    assert _stub_engines == ["javascript", "python"]
    assert stats.joern_flows == 2

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        engines = {row[0] for row in conn.execute("SELECT DISTINCT engine FROM flows").fetchall()}
    finally:
        conn.close()
    assert engines == {"joern"}


def test_run_hybrid_reuses_complete_fingerprint_without_rerunning_engines(
    tmp_path: Path,
    _stub_engines: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(semgrep_eng, "is_available", lambda: False)
    db_path = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    set_scan_stage(conn, fingerprint="same-inputs", engine="hybrid", stage="prep")
    conn.close()
    snapshot = tmp_path / "snap"
    project_root = snapshot / "app"
    project_root.mkdir(parents=True)
    repo_dir = tmp_path / "cache"
    repo_dir.mkdir()
    roots = [(project_root, "app", "javascript")]

    first = run_hybrid(
        roots,
        snapshot_root=snapshot,
        repo_dir=repo_dir,
        db_path=db_path,
        scan_fingerprint="same-inputs",
    )
    second = run_hybrid(
        roots,
        snapshot_root=snapshot,
        repo_dir=repo_dir,
        db_path=db_path,
        scan_fingerprint="same-inputs",
    )

    assert first.reused is False
    assert second.reused is True
    assert _stub_engines == ["javascript"]
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (1,)
    finally:
        conn.close()


def test_run_hybrid_auto_semgrep_completion_is_not_reusable(
    tmp_path: Path,
    _stub_engines: list[str],
) -> None:
    db_path = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    set_scan_stage(conn, fingerprint="same-inputs", engine="hybrid", stage="prep")
    conn.close()
    snapshot = tmp_path / "snap"
    project_root = snapshot / "app"
    project_root.mkdir(parents=True)
    repo_dir = tmp_path / "cache"
    repo_dir.mkdir()
    roots = [(project_root, "app", "javascript")]

    run_hybrid(
        roots,
        snapshot_root=snapshot,
        repo_dir=repo_dir,
        db_path=db_path,
        scan_fingerprint="same-inputs",
    )
    conn = duckdb.connect(str(db_path))
    assert conn.execute("SELECT stage FROM scan_cache_state").fetchone() == ("complete_unpinned",)
    set_scan_stage(conn, fingerprint="same-inputs", engine="hybrid", stage="prep")
    conn.close()

    second = run_hybrid(
        roots,
        snapshot_root=snapshot,
        repo_dir=repo_dir,
        db_path=db_path,
        scan_fingerprint="same-inputs",
    )
    assert second.reused is False
    assert _stub_engines == ["javascript", "javascript"]


def test_run_hybrid_failure_rolls_back_and_leaves_stage_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    set_scan_stage(conn, fingerprint="same-inputs", engine="hybrid", stage="prep")
    conn.close()
    snapshot = tmp_path / "snap"
    project_root = snapshot / "app"
    project_root.mkdir(parents=True)
    repo_dir = tmp_path / "cache"
    repo_dir.mkdir()

    def fail_semgrep(*_args, **_kwargs):
        raise RuntimeError("rule parse failed")

    monkeypatch.setattr(semgrep_eng, "is_available", lambda: True)
    monkeypatch.setattr(semgrep_eng, "run_semgrep", fail_semgrep)
    monkeypatch.setattr(joern_eng, "is_available", lambda: False)

    with pytest.raises(HybridStageError, match="rule parse failed"):
        run_hybrid(
            [(project_root, "app", "javascript")],
            snapshot_root=snapshot,
            repo_dir=repo_dir,
            db_path=db_path,
            scan_fingerprint="same-inputs",
        )

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        assert conn.execute("SELECT stage FROM scan_cache_state").fetchone() == ("prep",)
        assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (0,)
    finally:
        conn.close()


def test_run_hybrid_rejects_mismatched_or_incomplete_prep_generation(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "cache"
    repo_dir.mkdir()
    db_path = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    set_scan_stage(conn, fingerprint="old-inputs", engine="hybrid", stage="prep")
    conn.close()
    snapshot = repo_dir / "source"
    snapshot.mkdir()

    with pytest.raises(HybridStageError, match="no matching completed prep"):
        run_hybrid(
            [],
            snapshot_root=snapshot,
            repo_dir=repo_dir,
            db_path=db_path,
            scan_fingerprint="new-inputs",
        )

    (repo_dir / ".prep-incomplete").write_text("in progress\n", encoding="utf-8")
    with pytest.raises(HybridStageError, match="prep is incomplete"):
        run_hybrid(
            [],
            snapshot_root=snapshot,
            repo_dir=repo_dir,
            db_path=db_path,
            scan_fingerprint="old-inputs",
        )
