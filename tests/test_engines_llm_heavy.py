"""Tests for ai_codescan.engines.llm_heavy."""

from pathlib import Path

import duckdb

from ai_codescan.engines.llm_heavy import ingest_llm_heavy_flows
from ai_codescan.index.duckdb_schema import apply_schema


def _flow_row(*, fid: str = "L-001", file: str = "/abs/x.ts") -> dict[str, object]:
    return {
        "fid": fid,
        "cwe": "CWE-89",
        "source": {"file": file, "line": 13, "class": "http.body", "key": "name"},
        "sink": {"file": file, "line": 42, "class": "sql.exec", "lib": "pg"},
        "steps": [{"file": file, "line": 13}, {"file": file, "line": 42}],
    }


def test_ingest_llm_heavy_flows_inserts_rows(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)

    flows = tmp_path / "flows.jsonl"
    flows.write_text(
        "\n".join(
            [
                __import__("json").dumps(_flow_row()),
                __import__("json").dumps(_flow_row(fid="L-002", file="/abs/y.ts")),
            ]
        ),
        encoding="utf-8",
    )

    n = ingest_llm_heavy_flows(conn, flows_path=flows)
    assert n == 2
    rows = conn.execute("SELECT engine, cwe FROM flows ORDER BY fid").fetchall()
    assert rows == [("llm-heavy", "CWE-89"), ("llm-heavy", "CWE-89")]


def test_ingest_skips_invalid_lines(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    flows = tmp_path / "flows.jsonl"
    flows.write_text("not-json\n\n", encoding="utf-8")
    assert ingest_llm_heavy_flows(conn, flows_path=flows) == 0


def test_ingest_missing_file_returns_zero(tmp_path: Path) -> None:
    db = tmp_path / "z.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    assert ingest_llm_heavy_flows(conn, flows_path=tmp_path / "missing.jsonl") == 0
