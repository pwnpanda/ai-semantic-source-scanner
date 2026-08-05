"""Tests for ai_codescan.eval."""

from pathlib import Path

import duckdb
import pytest

from ai_codescan.eval import (
    EvalCase,
    ExpectedFinding,
    FlowRecord,
    compare_eval_results,
    flows_from_db,
    load_eval_cases,
    load_eval_results,
    miss_candidates_from_db,
    score_flows,
    write_eval_comparison,
    write_eval_outputs,
)
from ai_codescan.index.duckdb_schema import apply_schema


def _case(tmp_path: Path) -> EvalCase:
    return EvalCase(
        id="case-1",
        target=tmp_path,
        language="csharp",
        engine="joern",
        expected_findings=[
            ExpectedFinding(
                id="F-expected",
                cwe="CWE-89",
                file="Program.cs",
                source_line=10,
                sink_line=20,
                source_contains="id",
                sink_contains="ExecuteReader",
            )
        ],
    )


def test_load_eval_cases_from_manifest(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    manifest = tmp_path / "manifest.yml"
    manifest.write_text(
        """
default_engine: joern
cases:
  - id: tiny
    target: target
    language: csharp
    expected_findings:
      - id: E1
        cwe: CWE-89
        file: Program.cs
""",
        encoding="utf-8",
    )

    cases = load_eval_cases(manifest)

    assert len(cases) == 1
    assert cases[0].id == "tiny"
    assert cases[0].target == target
    assert cases[0].engine == "joern"
    assert cases[0].expected_findings[0].cwe == "CWE-89"


def test_load_eval_cases_defaults_to_hybrid(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    manifest = tmp_path / "manifest.yml"
    manifest.write_text(
        """
cases:
  - id: tiny
    target: target
    language: csharp
    expected_findings:
      - id: E1
        cwe: CWE-89
        file: Program.cs
""",
        encoding="utf-8",
    )

    cases = load_eval_cases(manifest)

    assert cases[0].engine == "hybrid"


def test_load_eval_cases_reads_target_local_eval_yaml(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "eval.yaml").write_text(
        """
language: python
expected_findings:
  - id: local
    cwe: CWE-22
    file: app.py
""",
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.yml"
    manifest.write_text(
        """
cases:
  - id: tiny
    target: target
    language: csharp
    expected_findings:
      - id: manifest
        cwe: CWE-89
        file: Program.cs
""",
        encoding="utf-8",
    )

    cases = load_eval_cases(manifest)

    assert cases[0].language == "python"
    assert cases[0].expected_findings[0].id == "local"


def test_load_eval_cases_validates_missing_target(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yml"
    manifest.write_text(
        """
cases:
  - id: missing
    target: nope
    language: csharp
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="does not exist"):
        load_eval_cases(manifest)


def test_load_eval_cases_validates_expected_findings_shape(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    manifest = tmp_path / "manifest.yml"
    manifest.write_text(
        """
cases:
  - id: malformed
    target: target
    language: csharp
    expected_findings:
      - id: E1
        cwe: CWE-89
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="required field: file"):
        load_eval_cases(manifest)


def test_flows_from_db_reads_final_scanner_flows(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute("INSERT INTO taint_sources VALUES ('T1', NULL, 'route', 'id', '/x.cs:10')")
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'ExecuteReader', 'unknown', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F1', 'T1', 'K1', 'CWE-89', 'codeql+joern', ?, '/ref', 'definite')",
        ['[["/repo/Program.cs", 10], ["/repo/Program.cs", 20]]'],
    )
    conn.close()

    flows = flows_from_db(db)

    assert flows == [
        FlowRecord(
            flow_id="F1",
            cwe="CWE-89",
            source_file="/repo/Program.cs",
            source_line=10,
            sink_file="/repo/Program.cs",
            sink_line=20,
            source_name="id",
            sink_name="ExecuteReader",
            engine="codeql+joern",
        )
    ]


def test_miss_candidates_from_db_reads_semantic_candidates(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    source = (tmp_path / "server.js").as_posix()
    conn.execute(
        """
        INSERT INTO entrypoints
        VALUES (NULL, 'http_route', 'app.delete /admin/users/{id}', ?, 12)
        """,
        [source],
    )
    conn.close()

    records = miss_candidates_from_db(db)

    cwes = {record.cwe for record in records}
    assert {"CWE-639", "CWE-862", "CWE-287"} <= cwes
    assert all(record.engine == "miss-finder" for record in records)


def test_score_flows_passes_on_precise_source_sink(tmp_path: Path) -> None:
    case = _case(tmp_path)
    result = score_flows(
        [
            FlowRecord(
                flow_id="joern-1",
                cwe="CWE-89",
                source_file="Program.cs",
                source_line=10,
                sink_file="Program.cs",
                sink_line=20,
                source_name="string id",
                sink_name="ExecuteReader",
            )
        ],
        case,
    )

    assert result.status == "pass"
    assert result.matches[0].status == "pass"


def test_score_flows_marks_partial_when_cwe_matches_but_precision_is_weak(tmp_path: Path) -> None:
    case = _case(tmp_path)
    result = score_flows(
        [
            FlowRecord(
                flow_id="joern-1",
                cwe="CWE-89",
                source_file="Program.cs",
                source_line=100,
                sink_file="Program.cs",
                sink_line=20,
                source_name="unknown",
                sink_name="ExecuteReader",
            )
        ],
        case,
    )

    assert result.status == "partial"
    assert result.matches[0].status == "partial"


def test_score_flows_full_match_on_cross_file_flow(tmp_path: Path) -> None:
    """Phase 14: a flow with source and sink in different files scores as a
    full pass when the expected finding pins source_file / sink_file."""
    case = EvalCase(
        id="cross-file",
        target=tmp_path,
        language="java",
        engine="joern",
        expected_findings=[
            ExpectedFinding(
                id="F-cross",
                cwe="CWE-89",
                file="Wrapper.java",
                source_file="Controller.java",
                source_line=17,
                sink_file="Wrapper.java",
                sink_line=18,
                source_contains="id",
                sink_contains="queryForObject",
            )
        ],
    )
    result = score_flows(
        [
            FlowRecord(
                flow_id="joern-1",
                cwe="CWE-89",
                source_file="src/Controller.java",
                source_line=17,
                sink_file="src/Wrapper.java",
                sink_line=18,
                source_name="@RequestParam String id",
                sink_name="queryForObject",
            )
        ],
        case,
    )

    assert result.status == "pass"
    assert result.matches[0].status == "pass"


def test_score_flows_cross_file_flow_is_partial_without_overrides(tmp_path: Path) -> None:
    """Without source_file / sink_file, a cross-file flow can only partial —
    the single `file` field can't match both endpoints. Confirms the
    fallback path is unchanged for existing single-file manifest entries."""
    case = EvalCase(
        id="cross-file-legacy",
        target=tmp_path,
        language="java",
        engine="joern",
        expected_findings=[
            ExpectedFinding(
                id="F-legacy",
                cwe="CWE-89",
                file="Wrapper.java",
                source_line=17,
                sink_line=18,
                source_contains="id",
                sink_contains="queryForObject",
            )
        ],
    )
    result = score_flows(
        [
            FlowRecord(
                flow_id="joern-1",
                cwe="CWE-89",
                source_file="src/Controller.java",
                source_line=17,
                sink_file="src/Wrapper.java",
                sink_line=18,
                source_name="@RequestParam String id",
                sink_name="queryForObject",
            )
        ],
        case,
    )

    assert result.status == "partial"


def test_score_flows_prefers_miss_over_false_positive(tmp_path: Path) -> None:
    case = _case(tmp_path)
    result = score_flows(
        [
            FlowRecord(
                flow_id="joern-1",
                cwe="CWE-22",
                source_file="Program.cs",
                source_line=10,
                sink_file="Program.cs",
                sink_line=20,
                source_name="id",
                sink_name="Open",
            )
        ],
        case,
    )

    assert result.status == "miss"
    assert result.matches[0].status == "miss"
    assert result.false_positives[0].cwe == "CWE-22"


def test_score_flows_skips_colocation_fallback_flows_from_fp_count(tmp_path: Path) -> None:
    """Recall-First Invariant 6: co-location-fallback flows are weak proximity
    evidence. They are visible in the candidate audit but eval treats them as
    acceptable noise — never counted as false positives. A real data-flow flow
    on the same shape still counts."""
    case = _case(tmp_path)
    result = score_flows(
        [
            FlowRecord(
                flow_id="joern-colo",
                cwe="CWE-22",  # different CWE from expected (CWE-89)
                source_file="Program.cs",
                source_line=10,
                sink_file="Program.cs",
                sink_line=20,
                source_name="id",
                sink_name="Open",
                flow_type="co-location",
            )
        ],
        case,
    )

    # CWE-89 expected, no match in flows → miss.
    # But the only unrelated flow has flow_type=co-location, so it must NOT
    # be counted as a false positive.
    assert result.false_positives == []


def test_score_flows_does_not_count_duplicate_matching_flows_as_false_positive(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    result = score_flows(
        [
            FlowRecord(
                flow_id="joern-1",
                cwe="CWE-89",
                source_file="Program.cs",
                source_line=10,
                sink_file="Program.cs",
                sink_line=20,
                source_name="string id",
                sink_name="ExecuteReader",
            ),
            FlowRecord(
                flow_id="semgrep-1",
                cwe="CWE-89",
                source_file="Program.cs",
                source_line=11,
                sink_file="Program.cs",
                sink_line=20,
                source_name="generic SQL injection message",
                sink_name="ExecuteReader",
            ),
        ],
        case,
    )

    assert result.status == "pass"
    assert result.false_positives == []


def test_score_flows_warns_but_does_not_error_when_no_flows(tmp_path: Path) -> None:
    case = _case(tmp_path)

    result = score_flows([], case)

    assert result.status == "miss"
    assert result.error == ""
    assert result.warnings == ["scanner completed but produced no flows"]


def test_load_and_compare_imported_ghost_results(tmp_path: Path) -> None:
    ai_path = tmp_path / "ai.jsonl"
    ghost_path = tmp_path / "ghost.json"
    ai_path.write_text(
        '{"case_id":"case-1","scanner":"ai-codescan","status":"pass","matches":[],"false_positives":[],"duration_sec":1.0,"warnings":[]}\n',
        encoding="utf-8",
    )
    ghost_path.write_text(
        '{"results":[{"case_id":"case-1","status":"miss","matches":[],"false_positives":[]}]}',
        encoding="utf-8",
    )

    ai = load_eval_results(ai_path, scanner="ai-codescan")
    ghost = load_eval_results(ghost_path, scanner="ghost")
    comparisons = compare_eval_results(ai, ghost)

    assert comparisons[0].case_id == "case-1"
    assert comparisons[0].delta == "ai-better"


def test_write_eval_comparison_outputs_jsonl_and_markdown(tmp_path: Path) -> None:
    comparison = compare_eval_results(
        [
            score_flows(
                [
                    FlowRecord(
                        flow_id="F1",
                        cwe="CWE-89",
                        source_file="Program.cs",
                        source_line=10,
                        sink_file="Program.cs",
                        sink_line=20,
                        source_name="id",
                        sink_name="ExecuteReader",
                    )
                ],
                _case(tmp_path),
            )
        ],
        [score_flows([], _case(tmp_path))],
    )

    jsonl = write_eval_comparison(comparison, out_dir=tmp_path / "out")

    assert jsonl.is_file()
    assert (tmp_path / "out" / "comparison.md").is_file()


def test_write_eval_outputs_includes_trend_rows(tmp_path: Path) -> None:
    result = score_flows(
        [
            FlowRecord(
                flow_id="F1",
                cwe="CWE-89",
                source_file="Program.cs",
                source_line=10,
                sink_file="Program.cs",
                sink_line=20,
                source_name="id",
                sink_name="ExecuteReader",
            )
        ],
        _case(tmp_path),
    )

    write_eval_outputs([result], out_dir=tmp_path / "out")

    assert (tmp_path / "out" / "trend.jsonl").is_file()
    trend = (tmp_path / "out" / "trend.md").read_text(encoding="utf-8")
    assert "TP" in trend
    assert "case-1" in trend
