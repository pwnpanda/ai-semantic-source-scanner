"""Tests for ai_codescan.report."""

import datetime as _dt
from pathlib import Path

from ai_codescan.findings.model import Finding
from ai_codescan.report import (
    derive_meta,
    render_report,
    report_filename,
    write_report,
)


def _finding(cwe: str = "CWE-89", title: str = "SQLi in handler", body: str = "") -> Finding:
    return Finding(
        finding_id="F-001",
        nomination_id="N-001",
        flow_id="F1",
        cwe=cwe,
        status="verified",
        title=title,
        body=body or "See `src/users.ts:42` for the concat.",
    )


def test_derive_meta_for_sqli() -> None:
    meta = derive_meta(_finding("CWE-89"), today=_dt.date(2026, 5, 9))
    assert meta.severity == "critical"
    assert meta.vuln_class == "sqli"
    assert meta.date == "2026-05-09"
    assert meta.component == "users"


def test_derive_meta_unknown_cwe_is_informational() -> None:
    meta = derive_meta(_finding(cwe="CWE-9999"))
    assert meta.severity == "informational"
    assert meta.vuln_class == "unknown"


def test_report_filename_matches_bugbounty_convention() -> None:
    meta = derive_meta(_finding("CWE-79"), today=_dt.date(2026, 1, 2))
    name = report_filename(meta)
    assert name == "2026-01-02--high--xss--users.md"


def test_render_report_includes_required_sections() -> None:
    md = render_report(_finding())
    for section in (
        "## Summary",
        "## Severity",
        "## Environment",
        "## Prerequisites",
        "## Reproduction Steps",
        "## Expected vs Actual",
        "## Evidence",
        "## Impact",
        "## Remediation",
        "## References",
    ):
        assert section in md


def test_write_report_writes_file_with_expected_name(tmp_path: Path) -> None:
    target = write_report(_finding(), report_dir=tmp_path / "report", today=_dt.date(2026, 5, 9))
    assert target.is_file()
    assert target.name == "2026-05-09--critical--sqli--users.md"
