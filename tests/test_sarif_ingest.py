"""Tests for ai_codescan.ingest.sarif."""

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.ingest.sarif import ingest_sarif


def test_ingest_sample_sarif_creates_source_sink_flow(tmp_path: Path, fixtures_dir: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)

    n = ingest_sarif(
        conn,
        sarif_path=fixtures_dir / "sample.sarif",
        project_id="tiny-vuln",
        snapshot_root=Path("/abs"),
        engine="codeql",
    )
    assert n == 1
    src_count = conn.execute("SELECT COUNT(*) FROM taint_sources").fetchone()
    assert src_count is not None
    assert src_count[0] == 1
    sink_count = conn.execute("SELECT COUNT(*) FROM taint_sinks").fetchone()
    assert sink_count is not None
    assert sink_count[0] == 1
    flow_count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()
    assert flow_count is not None
    assert flow_count[0] == 1
    cwe_row = conn.execute("SELECT cwe FROM flows").fetchone()
    assert cwe_row is not None
    assert cwe_row[0] == "CWE-89"
    eng_row = conn.execute("SELECT engine FROM flows").fetchone()
    assert eng_row is not None
    assert eng_row[0] == "codeql"


def test_ingest_is_idempotent(tmp_path: Path, fixtures_dir: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    ingest_sarif(
        conn,
        sarif_path=fixtures_dir / "sample.sarif",
        project_id="tiny-vuln",
        snapshot_root=Path("/abs"),
        engine="codeql",
    )
    ingest_sarif(
        conn,
        sarif_path=fixtures_dir / "sample.sarif",
        project_id="tiny-vuln",
        snapshot_root=Path("/abs"),
        engine="codeql",
    )
    flow_count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()
    assert flow_count is not None
    assert flow_count[0] == 1
