"""Tests for ai_codescan.engines.hybrid."""

import json
from pathlib import Path

import duckdb

from ai_codescan.engines.hybrid import dedupe_flows
from ai_codescan.index.duckdb_schema import apply_schema


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
