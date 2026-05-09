"""Tests for ai_codescan.findings.model."""

from ai_codescan.findings.model import Finding, parse_finding, render_finding


def test_render_then_parse_roundtrips() -> None:
    f = Finding(
        finding_id="F-001",
        nomination_id="N-001",
        flow_id="F1",
        cwe="CWE-89",
        status="unverified",
        title="SQL injection in users.ts:42",
        body="The handler concatenates `req.params.id` into a SQL query.",
    )
    md = render_finding(f)
    parsed = parse_finding(md)
    assert parsed == f


def test_parse_extracts_status_from_frontmatter() -> None:
    md = (
        "---\n"
        "finding_id: F-002\n"
        "nomination_id: N-014\n"
        'flow_id: ""\n'
        "cwe: CWE-639\n"
        "status: verified\n"
        'title: "IDOR in /orders/:id"\n'
        "---\n\n"
        "Body text.\n"
    )
    f = parse_finding(md)
    assert f.status == "verified"
    assert f.cwe == "CWE-639"
    assert f.flow_id == ""
