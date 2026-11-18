"""Tests for run-scoped candidate lineage."""

import json
from pathlib import Path

from ai_codescan.findings.model import Finding, render_finding
from ai_codescan.lineage import (
    record_candidates,
    refresh_candidate_lineage,
    write_report_manifest,
)


def _read_records(path: Path) -> dict[str, dict[str, object]]:
    return {
        row["candidate_id"]: row
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
        for row in [json.loads(line)]
    }


def test_lineage_tracks_reported_rejected_and_skipped_candidates(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "run-1"
    findings_dir = run_dir / "findings"
    findings_dir.mkdir(parents=True)
    record_candidates(
        run_dir,
        run_id="run-1",
        candidates=[
            {"id": "A-reported", "stream": "A", "score": 0.9},
            {"id": "A-rejected", "stream": "A", "score": 0.7},
            {"id": "A-test", "stream": "A", "skip_reason": "test-source"},
        ],
        selected_candidate_ids={"A-reported", "A-rejected"},
        origin="nominator",
    )
    (run_dir / "nominations.md").write_text(
        "# Nominations\n\n## Stream A\n\n"
        "- [ ] N-001 | api | sqli | src/a.ts:1 | rec: high | y/n: y\n"
        "    Candidate: A-reported\n\n"
        "- [ ] N-002 | api | xss | src/b.ts:2 | rec: med | y/n: n\n"
        "    Candidate: A-rejected\n",
        encoding="utf-8",
    )
    (run_dir / "findings_queue.md").write_text(
        "# Findings queue\n\n- [ ] N-001 | api | sqli | src/a.ts:1 | candidate: A-reported\n",
        encoding="utf-8",
    )
    finding = Finding(
        finding_id="F-001",
        nomination_id="N-001",
        flow_id="F1",
        cwe="CWE-89",
        status="verified",
        title="SQL injection",
        body="Evidence.",
        candidate_id="A-reported",
    )
    (findings_dir / "F-001.md").write_text(render_finding(finding), encoding="utf-8")
    report_path = tmp_path / "report" / "sql-injection.md"
    write_report_manifest(run_dir, [finding], [report_path])

    result = refresh_candidate_lineage(run_dir)

    assert result is not None
    records = _read_records(result[0])
    assert records["A-reported"]["final_state"] == "reported"
    assert records["A-reported"]["report_path"] == str(report_path)
    assert records["A-rejected"]["reason"] == "gate-rejected"
    assert records["A-test"]["reason"] == "test-source"
    assert "A-reported" in result[1].read_text(encoding="utf-8")


def test_lineage_marks_selected_miss_candidates_without_main_queue(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "run-2"
    record_candidates(
        run_dir,
        run_id="run-2",
        candidates=[{"id": "B-miss-selected"}, {"id": "B-miss-limited"}],
        selected_candidate_ids={"B-miss-selected"},
        origin="miss-finder",
    )

    result = refresh_candidate_lineage(run_dir)

    assert result is not None
    records = _read_records(result[0])
    assert records["B-miss-selected"]["analysis_selected"] is True
    assert records["B-miss-selected"]["reason"] == "miss-review-output-missing"
    assert records["B-miss-limited"]["analysis_selected"] is False
    assert records["B-miss-limited"]["reason"] == "review-limit"
