"""Tests for ai_codescan.proposal_routing_judge — Phase 7 LLM router."""

from __future__ import annotations

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.model_proposals import ModelProposal
from ai_codescan.proposal_routing_judge import parse_route_output
from ai_codescan.proposal_triage import triage_and_route


def _proposal(*, pid: str, cwe: str, language: str, sink: str = "") -> ModelProposal:
    return ModelProposal(
        proposal_id=pid,
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe=cwe,
        language=language,
        framework="",
        bug_class="",
        source_pattern="",
        sink_pattern=sink,
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="semgrep",
        eval_target="",
        rationale="",
        source_path="",
    )


def test_parse_route_output_pack_token() -> None:
    assert parse_route_output("pack:p/my-pack") == "pack:p/my-pack"


def test_parse_route_output_other_tokens() -> None:
    assert parse_route_output("custom-rule") == "custom-rule"
    assert parse_route_output("joern") == "joern"
    assert parse_route_output("unknown") is None
    assert parse_route_output("") is None
    assert parse_route_output("nothing matches here") is None


def test_triage_uses_llm_router_when_deterministic_misses(tmp_path: Path) -> None:
    """A (CWE-639, python) proposal has no _PACK_MAP entry. With an LLM
    router suggesting ``pack:p/custom-bola-pack``, triage_and_route uses
    that pack instead of leaving the proposal pending."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    def fake_router(_proposal):
        return "pack:p/custom-bola-pack"

    result = triage_and_route(
        [_proposal(pid="p-llm-routed", cwe="CWE-639", language="python")],
        conn=conn,
        repo_dir=tmp_path,
        llm_route=fake_router,
    )

    assert result["routed_to_pack"] == 1
    decision = conn.execute(
        "SELECT engine FROM proposal_decisions WHERE proposal_id = 'p-llm-routed'"
    ).fetchone()
    assert decision is not None
    assert decision[0] == "semgrep-pack:p/custom-bola-pack"


def test_triage_falls_back_when_llm_router_returns_none(tmp_path: Path) -> None:
    """Router returning None → deterministic pending-custom-rule path."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    def fake_router(_proposal):
        return None

    result = triage_and_route(
        [_proposal(pid="p-llm-none", cwe="CWE-639", language="python")],
        conn=conn,
        repo_dir=tmp_path,
        llm_route=fake_router,
    )

    assert result["pending_custom_rule"] == 1


def test_triage_falls_back_when_llm_router_raises(tmp_path: Path) -> None:
    """Router raising → deterministic path. Reporting must never fail."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    def fake_router(_proposal):
        raise RuntimeError("LLM down")

    result = triage_and_route(
        [_proposal(pid="p-llm-boom", cwe="CWE-639", language="python")],
        conn=conn,
        repo_dir=tmp_path,
        llm_route=fake_router,
    )

    assert result["pending_custom_rule"] == 1


def test_triage_does_not_call_llm_when_deterministic_hits(tmp_path: Path) -> None:
    """When _PACK_MAP already has a match, the LLM router is NOT consulted
    (saves a call). (CWE-89, python) is in the map."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    called: list[ModelProposal] = []

    def fake_router(p):
        called.append(p)
        return "pack:should-not-be-used"

    result = triage_and_route(
        [_proposal(pid="p-det-hit", cwe="CWE-89", language="python")],
        conn=conn,
        repo_dir=tmp_path,
        llm_route=fake_router,
    )

    assert result["routed_to_pack"] == 1
    assert called == []  # LLM router was NOT consulted
