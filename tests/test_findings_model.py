"""Tests for ai_codescan.findings.model."""

import pytest

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
        candidate_id="A-flow-17",
        exploitability="latent",
        unmet_prerequisites=("An internal administration route becomes reachable.",),
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


def test_parse_rejects_unknown_exploitability() -> None:
    md = "---\nstatus: unverified\nexploitability: future\n---\n\nBody\n"

    with pytest.raises(ValueError, match="unknown exploitability"):
        parse_finding(md)


def test_finding_requires_a_prerequisite_for_latent_exploitability() -> None:
    with pytest.raises(ValueError, match="at least one unmet prerequisite"):
        Finding(
            finding_id="F-1",
            nomination_id="N-1",
            flow_id="flow-1",
            cwe="CWE-918",
            status="unverified",
            title="title",
            body="body",
            exploitability="latent",
        )


def test_finding_rejects_prerequisite_without_latent_exploitability() -> None:
    with pytest.raises(ValueError, match="only a latent finding"):
        Finding(
            finding_id="F-1",
            nomination_id="N-1",
            flow_id="flow-1",
            cwe="CWE-918",
            status="unverified",
            title="title",
            body="body",
            unmet_prerequisites=("A route becomes reachable.",),
        )


@pytest.mark.parametrize(
    "prerequisites",
    ["one condition", {"condition": "value"}, ["valid", 2]],
)
def test_parse_rejects_invalid_prerequisites(prerequisites: object) -> None:
    md = f"---\nstatus: unverified\nunmet_prerequisites: {prerequisites!r}\n---\n\nBody\n"

    with pytest.raises(ValueError, match="list of strings"):
        parse_finding(md)


@pytest.mark.parametrize(
    "frontmatter",
    ["[unterminated", "- list-item", "scalar"],
)
def test_parse_rejects_malformed_or_non_mapping_frontmatter(frontmatter: str) -> None:
    with pytest.raises(ValueError, match="frontmatter"):
        parse_finding(f"---\n{frontmatter}\n---\n\nBody\n")
