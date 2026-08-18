"""Tests for ai_codescan.evidence."""

import json
from pathlib import Path

import duckdb

from ai_codescan.evidence import (
    build_evidence_bundle,
    render_bundle_markdown,
    write_evidence_bundle,
)
from ai_codescan.index.duckdb_schema import apply_schema


def _seed(conn: duckdb.DuckDBPyConnection, file: Path) -> None:
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'cs', 'p', 100)", [file.as_posix()])
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', NULL, 'route', 'string id', ?)",
        [f"{file.as_posix()}:15"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'ExecuteReader', 'unknown', '[]')"
    )
    steps = json.dumps([[file.as_posix(), 15, 15], [file.as_posix(), 19, 19]])
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'joern', ?, '/jsonl', 'inferred')",
        [steps],
    )
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'MapGet /users/{id}', ?, 14)",
        [file.as_posix()],
    )


def test_build_evidence_bundle_for_flow_candidate(tmp_path: Path) -> None:
    source = tmp_path / "Program.cs"
    source.write_text(
        "\n".join(
            [
                "// 1",
                "// 2",
                "// 3",
                "// 4",
                "// 5",
                "// 6",
                "// 7",
                "// 8",
                "// 9",
                "// 10",
                "// 11",
                "// 12",
                "// 13",
                'app.MapGet("/users/{id}", (string id) =>',
                "{",
                '    var sql = "SELECT " + id;',
                "    using var cmd = new SqliteCommand(sql, connection);",
                "    using var reader = cmd.ExecuteReader();",
                "});",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn, source)

    bundle = build_evidence_bundle(
        conn,
        {
            "id": "A-F1",
            "stream": "A",
            "fid": "F1",
            "score": 0.9,
            "score_label": "high",
            "score_factors": [{"name": "static_flow", "value": 0.22, "reason": "flow"}],
            "mitigations": [
                {
                    "kind": "sqli.bound-parameter",
                    "confidence": "high",
                    "reason": "parameters",
                    "evidence": "cmd.Parameters",
                }
            ],
        },
        source_root=tmp_path,
        context_lines=1,
    )

    assert bundle.cwe == "CWE-89"
    assert bundle.source_name == "string id"
    assert bundle.sink_name == "ExecuteReader"
    assert bundle.mitigations[0]["kind"] == "sqli.bound-parameter"
    assert bundle.entrypoints[0].signature == "MapGet /users/{id}"
    assert any("ExecuteReader" in excerpt.code_excerpt for excerpt in bundle.excerpts)
    assert "Mitigation Signals" in render_bundle_markdown(bundle)


def test_write_evidence_bundle_outputs_json_and_markdown(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    source = tmp_path / "x.cs"
    source.write_text("var id = input;\n", encoding="utf-8")
    bundle = build_evidence_bundle(
        conn,
        {
            "id": "B-auth-S1",
            "stream": "B",
            "file": source.as_posix(),
            "line": 1,
            "source_loc": source.as_posix(),
        },
        source_root=tmp_path,
    )

    json_path, md_path = write_evidence_bundle(bundle, bundles_dir=tmp_path / "bundles")

    assert json_path.is_file()
    assert md_path.is_file()
    assert "Evidence Bundle" in render_bundle_markdown(bundle)
    assert bundle.source_loc == f"{source.as_posix()}:1"


def test_secret_candidate_redacts_literal_from_every_evidence_format(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    source = tmp_path / "application.yml"
    source.write_text(
        "kafka:\n"
        "  schema-registry:\n"
        "    user-info: audit-user:do-not-leak\n"
        "    client-secret: neighboring-secret\n"
        '    "backup-token": quoted-neighboring-secret\n',
        encoding="utf-8",
    )
    bundle = build_evidence_bundle(
        conn,
        {
            "id": "B-secret",
            "stream": "B",
            "vector": "secrets/yaml-user-info-literal",
            "file": source.as_posix(),
            "line": 3,
            "evidence": "user-info: <redacted literal>",
            "requires_llm_validation": False,
        },
        source_root=tmp_path,
    )

    serialized = json.dumps(bundle.to_jsonable()) + render_bundle_markdown(bundle)
    assert "do-not-leak" not in serialized
    assert "neighboring-secret" not in serialized
    assert "quoted-neighboring-secret" not in serialized
    assert "user-info: <redacted>" in serialized
    assert '"backup-token": <redacted>' in serialized
    assert bundle.source_loc == f"{source.as_posix()}:3"


def test_evidence_bundle_does_not_read_poisoned_path_outside_snapshot(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    outside = tmp_path / "outside.kt"
    outside.write_text("outside evidence sentinel\n", encoding="utf-8")
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    bundle = build_evidence_bundle(
        conn,
        {
            "id": "poisoned",
            "stream": "B",
            "file": outside.as_posix(),
            "line": 1,
        },
        source_root=source_root,
    )

    assert bundle.excerpts[0].code_excerpt == ""
    assert "outside evidence sentinel" not in render_bundle_markdown(bundle)


def test_evidence_bundle_resolves_relative_db_paths_from_snapshot(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source = source_root / "src" / "Handler.kt"
    source.parent.mkdir(parents=True)
    source.write_text("val controlled = request.input\nexecute(controlled)\n", encoding="utf-8")
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', NULL, 'http', 'input', 'src/Handler.kt:1')"
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'execute', 'unknown', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'test', ?, NULL, 'inferred')",
        [json.dumps([["src/Handler.kt", 1], ["src/Handler.kt", 2]])],
    )

    bundle = build_evidence_bundle(
        conn,
        {"id": "relative", "stream": "A", "fid": "F1"},
        source_root=source_root,
    )

    assert len(bundle.excerpts) == 2
    assert all(excerpt.file == source.as_posix() for excerpt in bundle.excerpts)
    assert "request.input" in bundle.excerpts[0].code_excerpt
