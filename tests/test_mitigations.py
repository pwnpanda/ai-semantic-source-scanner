"""Tests for mitigation annotation helpers."""

from __future__ import annotations

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.mitigations import (
    detect_authz_mitigations,
    detect_command_mitigations,
    detect_logging_mitigations,
    detect_mass_assignment_mitigations,
    detect_path_mitigations,
    detect_sqli_mitigations,
    detect_ssrf_mitigations,
    detect_xss_mitigations,
    mitigations_for_candidate,
)


def test_detect_sqli_mitigations_positive_and_negative() -> None:
    assert detect_sqli_mitigations('cmd.Parameters.AddWithValue("@id", id)')
    assert detect_sqli_mitigations("anything", parameterization="parameterized")
    assert detect_sqli_mitigations('var sql = "SELECT " + id') == []


def test_detect_sqli_mitigations_python_parameterized_execute() -> None:
    """Python DB-API: execute(sql, (val,)) is parameterized and safe."""
    assert detect_sqli_mitigations("cursor.execute(query, (user_id,))")
    assert detect_sqli_mitigations("cursor.execute(sql, [a, b])")
    # String-concatenated SQL — must NOT match the parameterized rule.
    assert not any(
        s.kind == "sqli.python-parameterized-execute"
        for s in detect_sqli_mitigations('cursor.execute("SELECT " + user_id)')
    )


def test_detect_sqli_mitigations_multiline_parameterized_execute() -> None:
    """Phase 3 callout fix: multi-line execute(sql,\\n  params,\\n) must match."""
    multiline = """
    cursor.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
    )
    """
    assert any(
        s.kind == "sqli.python-parameterized-execute" for s in detect_sqli_mitigations(multiline)
    )


def test_detect_command_mitigations_positive_and_negative() -> None:
    assert detect_command_mitigations("subprocess.run(args, shell=False)")
    assert detect_command_mitigations("exec(user_input)") == []


def test_detect_path_mitigations_positive_and_negative() -> None:
    assert detect_path_mitigations("root = realpath(base); assert commonpath([root, path])")
    assert detect_path_mitigations("open(user_path)") == []


def test_detect_xss_mitigations_positive_and_negative() -> None:
    assert detect_xss_mitigations("element.textContent = value")
    assert detect_xss_mitigations("element.innerHTML = value") == []


def test_detect_ssrf_mitigations_positive_and_negative() -> None:
    assert detect_ssrf_mitigations("if host in allowed_hosts: fetch(url)")
    assert detect_ssrf_mitigations("fetch(request.args['url'])") == []


def test_detect_authz_mitigations_positive_and_negative() -> None:
    assert detect_authz_mitigations("app.MapGet(...).RequireAuthorization()")
    assert detect_authz_mitigations("return db.Users.Find(id)") == []


def test_detect_mass_assignment_mitigations_positive_and_negative() -> None:
    assert detect_mass_assignment_mitigations("const dto = pick(body, ['name'])")
    assert detect_mass_assignment_mitigations("User.update(req.body)") == []


def test_detect_logging_mitigations_positive_and_negative() -> None:
    assert detect_logging_mitigations("const safe = redact(req.body); logger.info(safe)")
    assert detect_logging_mitigations("delete payload.password\nconsole.log(payload)")
    assert detect_logging_mitigations("logger.info(req.headers.authorization)") == []


def test_mitigations_for_candidate_reads_flow_context(tmp_path: Path) -> None:
    source = tmp_path / "Program.cs"
    source.write_text(
        "\n".join(
            [
                'var sql = "SELECT id FROM users WHERE id = @id";',
                "using var cmd = new SqliteCommand(sql, connection);",
                'cmd.Parameters.AddWithValue("@id", id);',
                "cmd.ExecuteReader();",
            ]
        ),
        encoding="utf-8",
    )
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    conn.execute("INSERT INTO taint_sources VALUES ('T1', NULL, 'route', 'id', ?)", [f"{source}:1"])
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'ExecuteReader', 'unknown', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'joern', ?, NULL, 'inferred')",
        [f'[["{source}", 1], ["{source}", 4]]'],
    )

    signals = mitigations_for_candidate(
        conn,
        {
            "id": "A-F1",
            "stream": "A",
            "fid": "F1",
            "cwe": "CWE-89",
            "sink_class": "sql.exec",
            "parameterization": "unknown",
        },
        source_root=tmp_path,
    )

    assert {signal["kind"] for signal in signals} >= {"sqli.bound-parameter"}
