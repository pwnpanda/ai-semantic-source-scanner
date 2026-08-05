"""Tests for ai_codescan.severity_judge — Phase 7 LLM severity judge."""

from __future__ import annotations

from ai_codescan.findings.model import Finding
from ai_codescan.report import derive_meta
from ai_codescan.severity_judge import parse_judge_output


def _finding(cwe: str = "CWE-89") -> Finding:
    return Finding(
        finding_id="F-1",
        nomination_id="N-1",
        flow_id="F1",
        cwe=cwe,
        status="verified",
        title="SQLi",
        body="See `src/users.ts:42`.",
    )


def test_parse_judge_output_accepts_bare_token() -> None:
    assert parse_judge_output("high") == "high"
    assert parse_judge_output("CRITICAL") == "critical"


def test_parse_judge_output_finds_token_inside_prose() -> None:
    assert parse_judge_output("After review, I think this is HIGH severity.") == "high"


def test_parse_judge_output_unchanged_returns_none() -> None:
    assert parse_judge_output("UNCHANGED") is None
    assert parse_judge_output("My answer: unchanged") is None


def test_parse_judge_output_returns_none_for_garbage() -> None:
    assert parse_judge_output("") is None
    assert parse_judge_output("I don't know") is None


def test_derive_meta_uses_llm_judge_when_provided() -> None:
    """The judge's verdict overrides the deterministic calc when it returns
    a valid tier."""
    captured: dict = {}

    def fake_judge(*, cwe, vuln_class, body, base_severity, score_factors):
        captured["cwe"] = cwe
        captured["base_severity"] = base_severity
        return "low"  # downgrade from default critical

    meta = derive_meta(_finding("CWE-89"), llm_judge=fake_judge)
    assert meta.severity == "low"
    assert captured["cwe"] == "CWE-89"
    assert captured["base_severity"] == "critical"  # baseline passed in


def test_derive_meta_falls_back_when_judge_returns_none() -> None:
    """A judge returning None (e.g. 'UNCHANGED') means keep the deterministic."""

    def fake_judge(**_):
        return None

    meta = derive_meta(_finding("CWE-89"), llm_judge=fake_judge)
    assert meta.severity == "critical"  # baseline preserved


def test_derive_meta_falls_back_when_judge_raises() -> None:
    """A judge that raises must NEVER break reporting (recall-first)."""

    def fake_judge(**_):
        raise RuntimeError("LLM exploded")

    meta = derive_meta(_finding("CWE-89"), llm_judge=fake_judge)
    assert meta.severity == "critical"


def test_derive_meta_judge_only_accepts_valid_tier() -> None:
    """A judge returning a non-tier string is ignored (deterministic stays)."""

    def fake_judge(**_):
        return "not-a-tier"

    meta = derive_meta(_finding("CWE-89"), llm_judge=fake_judge)
    assert meta.severity == "critical"
