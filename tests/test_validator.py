"""Tests for ai_codescan.validator (status-flip logic + log writer)."""

from pathlib import Path

import pytest

from ai_codescan.findings.model import Finding, parse_finding, render_finding
from ai_codescan.runs.state import load_or_create
from ai_codescan.sandbox import SandboxResult
from ai_codescan.validator import _flip_status, _hints_for_cwe, _parse_verdict, run_validator


def _result(exit_code: int = 0, *, signal: bool = False, timed_out: bool = False) -> SandboxResult:
    return SandboxResult(
        exit_code=exit_code,
        stdout="OK_VULN" if signal else "BENIGN",
        stderr="",
        duration_sec=0.1,
        signal_seen=signal,
        timed_out=timed_out,
    )


def test_flip_verified_when_signal_seen() -> None:
    status, _ = _flip_status(_result(0, signal=True))
    assert status == "verified"


def test_flip_rejected_when_clean_exit_no_signal() -> None:
    status, _ = _flip_status(_result(0, signal=False))
    assert status == "rejected"


def test_flip_inconclusive_when_nonzero_exit() -> None:
    status, _ = _flip_status(_result(1, signal=False))
    assert status == "poc_inconclusive"


def test_flip_inconclusive_when_timed_out() -> None:
    status, _ = _flip_status(_result(124, signal=False, timed_out=True))
    assert status == "poc_inconclusive"


def test_run_validator_writes_log_when_no_pocs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    state = load_or_create(repo_dir, engine="codeql", temperature=0.0, target_bug_classes=[])
    findings_dir = state.run_dir / "findings"
    findings_dir.mkdir()
    (findings_dir / "F-001.md").write_text(
        render_finding(
            Finding(
                finding_id="F-001",
                nomination_id="N-001",
                flow_id="F1",
                cwe="CWE-89",
                status="unverified",
                title="t",
                body="b",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", "/nonexistent")  # No claude/gemini/codex; skill loop skipped.

    log_path = run_validator(state, repo_dir=repo_dir)
    assert log_path.is_file()
    log_text = log_path.read_text(encoding="utf-8")
    assert "Validation log" in log_text
    # No PoC was authored, so the finding stays unverified.
    f = parse_finding((findings_dir / "F-001.md").read_text(encoding="utf-8"))
    assert f.status == "unverified"


def test_parse_verdict_extracts_json_block() -> None:

    stdout = (
        "running PoC...\n"
        "observed: response body matches expected SQL error\n"
        '{"verdict": "vulnerable", "evidence": ["sql syntax error"], "confidence": 0.92}\n'
    )
    parsed = _parse_verdict(stdout)
    assert parsed is not None
    assert parsed["verdict"] == "vulnerable"
    assert parsed["confidence"] == 0.92


def test_parse_verdict_returns_none_on_garbage() -> None:

    assert _parse_verdict("hello world") is None
    assert _parse_verdict('{"oops": true}') is None
    assert _parse_verdict("{not even json}") is None


def test_flip_status_uses_json_verdict_when_present() -> None:
    result = SandboxResult(
        exit_code=0,
        stdout='{"verdict": "vulnerable", "evidence": [], "confidence": 0.7}',
        stderr="",
        duration_sec=0.0,
        signal_seen=False,
        timed_out=False,
        runtime="docker",
    )
    status, parsed = _flip_status(result)
    assert status == "verified"
    assert parsed is not None and parsed["confidence"] == 0.7


def test_flip_status_falls_back_to_signal_when_no_json() -> None:
    result = SandboxResult(
        exit_code=0,
        stdout="OK_VULN",
        stderr="",
        duration_sec=0.0,
        signal_seen=True,
        timed_out=False,
        runtime="docker",
    )
    status, parsed = _flip_status(result)
    assert status == "verified"
    assert parsed is None


def test_flip_status_rejected_on_clean_run_without_signal() -> None:
    result = SandboxResult(
        exit_code=0,
        stdout="just some output, no signal",
        stderr="",
        duration_sec=0.0,
        signal_seen=False,
        timed_out=False,
        runtime="docker",
    )
    status, parsed = _flip_status(result)
    assert status == "rejected"
    assert parsed is None


def test_hints_for_cwe_returns_taxonomy_hints() -> None:

    sqli_hints = _hints_for_cwe("CWE-89")
    assert sqli_hints
    assert any("sql" in h.lower() for h in sqli_hints)


def test_hints_for_cwe_returns_empty_for_unknown() -> None:

    assert _hints_for_cwe("CWE-9999") == []
    assert _hints_for_cwe(None) == []
