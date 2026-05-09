"""Tests for ai_codescan.validator (status-flip logic + log writer)."""

from pathlib import Path

import pytest

from ai_codescan.findings.model import Finding, parse_finding, render_finding
from ai_codescan.runs.state import load_or_create
from ai_codescan.sandbox import SandboxResult
from ai_codescan.validator import _flip_status, run_validator


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
    assert _flip_status(_result(0, signal=True)) == "verified"


def test_flip_rejected_when_clean_exit_no_signal() -> None:
    assert _flip_status(_result(0, signal=False)) == "rejected"


def test_flip_inconclusive_when_nonzero_exit() -> None:
    assert _flip_status(_result(1, signal=False)) == "poc_inconclusive"


def test_flip_inconclusive_when_timed_out() -> None:
    assert _flip_status(_result(124, signal=False, timed_out=True)) == "poc_inconclusive"


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
