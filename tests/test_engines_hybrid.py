"""Tests for ai_codescan.engines.hybrid."""

import json
from pathlib import Path

import duckdb
import pytest

from ai_codescan.engines import joern as joern_eng
from ai_codescan.engines import semgrep as semgrep_eng
from ai_codescan.engines.hybrid import dedupe_flows, run_hybrid
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
