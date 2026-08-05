"""Tests for ai_codescan.proposal_clone_rewrite — Phase 7 LLM rewriter."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ai_codescan.cli import app
from ai_codescan.model_proposals import ModelProposal, write_model_proposals
from ai_codescan.proposal_clone_rewrite import parse_rewrite_output

runner = CliRunner()


def test_parse_rewrite_output_strips_fences() -> None:
    raw = "```\n(?i)^(fetch)$\n```"
    assert parse_rewrite_output(raw) == "(?i)^(fetch)$"


def test_parse_rewrite_output_takes_first_line() -> None:
    raw = "(?i)^(fetch)$\n# explanation: this matches bare fetch calls\n"
    assert parse_rewrite_output(raw) == "(?i)^(fetch)$"


def test_parse_rewrite_output_empty_returns_none() -> None:
    assert parse_rewrite_output("") is None
    assert parse_rewrite_output("\n\n") is None


def test_clone_without_llm_keeps_original_sink_pattern(tmp_path: Path) -> None:
    """No --rewrite-with-llm: clone preserves the source sink_pattern as-is."""
    cache = tmp_path / "cache"
    run_dir = cache / "repo-1" / "runs" / "run-1"
    proposals_dir = run_dir / "model_proposals"
    src = ModelProposal(
        proposal_id="p-src",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-918",
        language="python",
        framework="",
        bug_class="ssrf",
        source_pattern="",
        sink_pattern="$CLIENT.fetch($URL)",  # Semgrep-shaped
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="semgrep",
        eval_target="",
        rationale="",
        source_path="",
    )
    write_model_proposals([src], proposals_dir=proposals_dir)

    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "clone",
            "p-src",
            "--repo-id",
            "repo-1",
            "--engine",
            "joern",
        ],
    )

    assert result.exit_code == 0, result.output
    cloned_payload = json.loads((proposals_dir / "p-src-joern.json").read_text(encoding="utf-8"))
    assert cloned_payload["sink_pattern"] == "$CLIENT.fetch($URL)"  # preserved


def test_clone_with_llm_rewrite_warns_when_unavailable(tmp_path: Path, monkeypatch) -> None:
    """--rewrite-with-llm but no LLM CLI on PATH: warns and keeps original."""
    # The CLI rejects unknown providers; use a known one but blank the PATH
    # so is_available returns False inside make_llm_rewriter.
    monkeypatch.setenv("PATH", "/nonexistent")
    cache = tmp_path / "cache"
    run_dir = cache / "repo-1" / "runs" / "run-1"
    proposals_dir = run_dir / "model_proposals"
    src = ModelProposal(
        proposal_id="p-src",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-918",
        language="python",
        framework="",
        bug_class="ssrf",
        source_pattern="",
        sink_pattern="$CLIENT.fetch($URL)",
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="semgrep",
        eval_target="",
        rationale="",
        source_path="",
    )
    write_model_proposals([src], proposals_dir=proposals_dir)

    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "clone",
            "p-src",
            "--repo-id",
            "repo-1",
            "--engine",
            "joern",
            "--rewrite-with-llm",
            "--llm-provider",
            "claude",
        ],
    )

    assert result.exit_code == 0, result.output
    # LLM unavailable → fell back to original; clone still succeeded.
    cloned_payload = json.loads((proposals_dir / "p-src-joern.json").read_text(encoding="utf-8"))
    assert cloned_payload["sink_pattern"] == "$CLIENT.fetch($URL)"
    # Warning message in stderr/stdout (mingled in typer runner).
    assert "LLM rewriter unavailable" in result.output or "warning" in result.output
