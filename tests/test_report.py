"""Tests for ai_codescan.report."""

import datetime as _dt
from pathlib import Path

import duckdb

from ai_codescan.evidence import EvidenceBundle
from ai_codescan.findings.model import Finding
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.report import (
    ReportMeta,
    derive_meta,
    render_candidate_audit,
    render_report,
    report_filename,
    summary_from_body,
    write_candidate_audit,
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


def test_derive_meta_demotes_severity_when_mitigation_strong() -> None:
    """Phase 2: severity should drop one tier when a strong mitigation signal
    is present (e.g. SQL parameterization on a CWE-89 base=critical)."""
    factors = [
        {"name": "mitigation_signal", "value": -0.18, "reason": "sqli.parameterized-api"},
    ]
    meta = derive_meta(_finding("CWE-89"), score_factors=factors)
    assert meta.severity == "high", f"expected high (one tier below critical), got {meta.severity}"


def test_derive_meta_demotes_severity_when_colocation_fallback() -> None:
    """Phase 2: a co-location-fallback candidate should be downgraded a tier
    because the flow is proximity-only (Invariant 6)."""
    factors = [
        {"name": "colocation_fallback", "value": -0.32, "reason": "co-location"},
    ]
    meta = derive_meta(_finding("CWE-79"), score_factors=factors)
    assert meta.severity == "medium", f"expected medium (one tier below high), got {meta.severity}"


def test_derive_meta_promotes_severity_when_engine_consensus() -> None:
    """Phase 2: multi-engine agreement bumps severity one tier (caps at critical)."""
    factors = [
        {"name": "engine_consensus", "value": 0.24, "reason": "codeql+joern"},
    ]
    meta = derive_meta(_finding("CWE-639"), score_factors=factors)
    assert meta.severity == "high", f"expected high (one tier above medium), got {meta.severity}"


def test_derive_meta_static_when_no_factors() -> None:
    """Phase 2: no score factors → fall back to static CWE mapping."""
    assert derive_meta(_finding("CWE-89")).severity == "critical"
    assert derive_meta(_finding("CWE-639")).severity == "medium"


def test_derive_meta_caps_at_critical_and_informational() -> None:
    """Phase 2: severity calculations clamp to {critical … informational}."""
    factors_up = [
        {"name": "engine_consensus", "value": 0.24, "reason": "x"},
        {"name": "entrypoint_proximity", "value": 0.16, "reason": "y"},
    ]
    # CWE-89 is already critical → stays critical even with two boosts.
    meta = derive_meta(_finding("CWE-89"), score_factors=factors_up)
    assert meta.severity == "critical"

    factors_down = [
        {"name": "mitigation_signal", "value": -0.18, "reason": "a"},
        {"name": "colocation_fallback", "value": -0.32, "reason": "b"},
        {"name": "low_signal_path", "value": -0.35, "reason": "c"},
    ]
    # CWE-532 is base=low → cannot drop below informational.
    meta = derive_meta(_finding("CWE-532"), score_factors=factors_down)
    assert meta.severity == "informational"


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


def test_render_report_includes_bundle_and_review_verdict() -> None:
    bundle = EvidenceBundle(
        bundle_id="E-N-001",
        candidate_id="N-001",
        stream="A",
        flow_id="F1",
        cwe="CWE-89",
        source_loc="src/users.ts:42",
        source_name="req.body.id",
        sink_name="query",
        sink_class="sql.exec",
        parameterization="unknown",
        engine="codeql+joern",
        confidence="definite",
        score=0.9,
        score_label="high",
        score_factors=[{"name": "static_flow", "value": 0.22, "reason": "flow"}],
        mitigations=[
            {
                "kind": "sqli.bound-parameter",
                "confidence": "high",
                "reason": "parameters",
            }
        ],
    )

    md = render_report(
        _finding(),
        bundle=bundle,
        review_verdict={
            "verdict": "true-positive",
            "confidence": "high",
            "reviewer": "deep_analyzer",
        },
    )

    assert "## Scanner Evidence" in md
    assert "codeql+joern" in md
    assert "sqli.bound-parameter" in md
    assert "## Review Verdict" in md
    assert "true-positive" in md


def test_write_report_writes_file_with_expected_name(tmp_path: Path) -> None:
    target = write_report(_finding(), report_dir=tmp_path / "report", today=_dt.date(2026, 5, 9))
    assert target.is_file()
    assert target.name == "2026-05-09--critical--sqli--users.md"


def test_candidate_audit_renders_scored_candidates(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    conn.execute(
        """
        INSERT INTO candidate_scores
          (
            candidate_id, flow_id, stream, score, label, processing_bucket,
            factors_json, scorer
          )
        VALUES ('N-001', 'F1', 'A', 0.9, 'high', 'report', '[]', 'test')
        """
    )

    md = render_candidate_audit(conn)
    path = write_candidate_audit(conn, report_dir=tmp_path / "report")

    assert "N-001" in md
    assert path.name == "candidate-audit.md"


def test_summary_skips_the_bodys_own_heading() -> None:
    """Analyser bodies open with ``## Summary``; the report must not echo it.

    Taking the body's first line yielded that heading verbatim, so reports
    rendered ``## Summary`` twice with no prose underneath.
    """
    body = "## Summary\nThe redirect target comes from the Host header.\n\n## Path\n- a\n"
    md = render_report(_finding(body=body))
    assert "## Summary\n\nThe redirect target comes from the Host header." in md
    assert "## Summary\n\n## Summary" not in md


def test_summary_skips_leading_code_fence() -> None:
    body = "## Summary\n\n```js\nres.redirect(x)\n```\n\nProse after the fence.\n"
    assert summary_from_body(body, fallback="fb") == "Prose after the fence."


def test_summary_falls_back_when_body_has_no_prose() -> None:
    assert summary_from_body("## Summary\n\n### Path\n", fallback="the title") == "the title"


def test_report_filename_strips_shell_hostile_characters() -> None:
    """Components are scraped from prose and pick up stray punctuation.

    Backticks and parentheses made real report files awkward to quote and
    invalid on Windows.
    """
    meta = ReportMeta(
        severity="medium",
        component="(`criiptoVerify",
        vuln_class="csrf",
        date="2026-08-04",
    )
    assert report_filename(meta) == "2026-08-04--medium--csrf--criiptoVerify.md"


def test_report_filename_survives_an_all_punctuation_component() -> None:
    meta = ReportMeta(severity="low", component="`()`", vuln_class="redos", date="2026-08-04")
    assert report_filename(meta) == "2026-08-04--low--redos--unknown.md"


def test_scanner_evidence_omits_empty_fields() -> None:
    """Stream B findings have no static flow, so engine/score/sink are empty."""
    bundle = EvidenceBundle(
        bundle_id="E-N-002",
        candidate_id="B-1",
        stream="B",
        flow_id="",
        cwe="",
        source_loc="src/a.ts:1",
        source_name="",
        sink_name="",
        sink_class="",
        parameterization="",
        engine="",
        confidence="",
        score=None,
        score_label="",
        score_factors=[],
        mitigations=[],
    )
    md = render_report(_finding(), bundle=bundle)
    assert "- Stream: B" in md
    assert "- Source: src/a.ts:1" in md
    assert "- Engine:" not in md
    assert "``" not in md.split("## Evidence")[0]
