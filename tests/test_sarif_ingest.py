"""Tests for ai_codescan.ingest.sarif."""

import copy
import json
from pathlib import Path

import duckdb
import pytest

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.ingest.sarif import ingest_sarif
from ai_codescan.source_paths import SourcePathError


def _set_result_uri(result: dict, uri: str) -> None:
    for location in result.get("locations", []):
        location["physicalLocation"]["artifactLocation"]["uri"] = uri
    for flow in result.get("codeFlows", []):
        for thread in flow.get("threadFlows", []):
            for step in thread.get("locations", []):
                physical = step["location"]["physicalLocation"]
                physical["artifactLocation"]["uri"] = uri


def _write_sarif_with_uri(fixtures_dir: Path, destination: Path, uri: str) -> None:
    payload = json.loads((fixtures_dir / "sample.sarif").read_text(encoding="utf-8"))
    _set_result_uri(payload["runs"][0]["results"][0], uri)
    destination.write_text(json.dumps(payload), encoding="utf-8")


def test_ingest_sample_sarif_creates_source_sink_flow(tmp_path: Path, fixtures_dir: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    snapshot_root = tmp_path / "source"
    snapshot_root.mkdir()
    (snapshot_root / "server.js").write_text("\n" * 8, encoding="utf-8")

    n = ingest_sarif(
        conn,
        sarif_path=fixtures_dir / "sample.sarif",
        project_id="tiny-vuln",
        snapshot_root=snapshot_root,
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
    snapshot_root = tmp_path / "source"
    snapshot_root.mkdir()
    (snapshot_root / "server.js").write_text("\n" * 8, encoding="utf-8")
    ingest_sarif(
        conn,
        sarif_path=fixtures_dir / "sample.sarif",
        project_id="tiny-vuln",
        snapshot_root=snapshot_root,
        engine="codeql",
    )
    ingest_sarif(
        conn,
        sarif_path=fixtures_dir / "sample.sarif",
        project_id="tiny-vuln",
        snapshot_root=snapshot_root,
        engine="codeql",
    )
    flow_count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()
    assert flow_count is not None
    assert flow_count[0] == 1


@pytest.mark.parametrize(
    "bad_uri",
    ("/etc/passwd", "../outside.js", "%2e%2e/outside.js", "linked.js"),
)
def test_ingest_rejects_sarif_paths_outside_snapshot(
    tmp_path: Path,
    fixtures_dir: Path,
    bad_uri: str,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    outside = tmp_path / "outside.js"
    outside.write_text("outside SARIF sentinel\n", encoding="utf-8")
    (source_root / "linked.js").symlink_to(outside)
    sarif = tmp_path / "poisoned.sarif"
    _write_sarif_with_uri(fixtures_dir, sarif, bad_uri)
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    with pytest.raises(SourcePathError, match="escapes snapshot"):
        ingest_sarif(
            conn,
            sarif_path=sarif,
            project_id="poisoned",
            snapshot_root=source_root,
            engine="semgrep",
        )

    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (0,)


@pytest.mark.parametrize("scheme", ("https://example.test/source.js", "file://remote/etc/passwd"))
def test_ingest_rejects_remote_sarif_uri(
    tmp_path: Path,
    fixtures_dir: Path,
    scheme: str,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    sarif = tmp_path / "remote.sarif"
    _write_sarif_with_uri(fixtures_dir, sarif, scheme)
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    with pytest.raises(SourcePathError, match="unsupported scheme|remote authority"):
        ingest_sarif(
            conn,
            sarif_path=sarif,
            project_id="remote",
            snapshot_root=source_root,
            engine="semgrep",
        )


@pytest.mark.parametrize("uri_kind", ("relative", "absolute", "encoded-file-uri"))
def test_ingest_accepts_contained_sarif_uri_forms(
    tmp_path: Path,
    fixtures_dir: Path,
    uri_kind: str,
) -> None:
    source_root = tmp_path / "source"
    if uri_kind == "encoded-file-uri":
        source = source_root / "space dir" / "server file.js"
    else:
        source = source_root / "server.js"
    source.parent.mkdir(parents=True)
    source.write_text("\n" * 8, encoding="utf-8")
    uri = {
        "relative": "server.js",
        "absolute": source.as_posix(),
        "encoded-file-uri": source.as_uri(),
    }[uri_kind]
    sarif = tmp_path / "valid.sarif"
    _write_sarif_with_uri(fixtures_dir, sarif, uri)
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    count = ingest_sarif(
        conn,
        sarif_path=sarif,
        project_id=uri_kind,
        snapshot_root=source_root,
        engine="semgrep",
    )

    assert count == 1
    steps = conn.execute("SELECT steps_json FROM flows").fetchone()
    assert steps is not None
    assert {step[0] for step in json.loads(steps[0])} == {source.as_posix()}


def test_ingest_validates_all_sarif_paths_before_inserting(
    tmp_path: Path,
    fixtures_dir: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "server.js"
    source.write_text("\n" * 8, encoding="utf-8")
    payload = json.loads((fixtures_dir / "sample.sarif").read_text(encoding="utf-8"))
    valid_result = payload["runs"][0]["results"][0]
    poisoned_result = copy.deepcopy(valid_result)
    _set_result_uri(poisoned_result, "/etc/passwd")
    payload["runs"][0]["results"].append(poisoned_result)
    sarif = tmp_path / "mixed.sarif"
    sarif.write_text(json.dumps(payload), encoding="utf-8")
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    with pytest.raises(SourcePathError, match="escapes snapshot"):
        ingest_sarif(
            conn,
            sarif_path=sarif,
            project_id="mixed",
            snapshot_root=source_root,
            engine="semgrep",
        )

    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (0,)
    assert conn.execute("SELECT COUNT(*) FROM taint_sources").fetchone() == (0,)
    assert conn.execute("SELECT COUNT(*) FROM taint_sinks").fetchone() == (0,)
