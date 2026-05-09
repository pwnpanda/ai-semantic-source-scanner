"""Drive the validator skill end-to-end and execute PoCs in the sandbox."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import cast

from ai_codescan.findings.model import Finding, Status, parse_finding, render_finding
from ai_codescan.llm import LLMConfig, is_available
from ai_codescan.nominator import write_llm_cmd_script
from ai_codescan.runs.state import RunState, save
from ai_codescan.sandbox import (
    DEFAULT_SIGNAL,
    SandboxResult,
    SandboxUnavailableError,
    image_for_lang,
    run_in_sandbox,
)

SKILL_DIR = Path(__file__).resolve().parent / "skills" / "validator"


def _flip_status(result: SandboxResult) -> str:
    if result.signal_seen:
        return "verified"
    if result.exit_code == 0 and not result.timed_out:
        return "rejected"
    return "poc_inconclusive"


def _validation_log_row(finding_id: str, status: str, result: SandboxResult) -> str:
    return (
        f"| {finding_id} | {status} | exit={result.exit_code} "
        f"| signal={'y' if result.signal_seen else 'n'} "
        f"| timed_out={'y' if result.timed_out else 'n'} |"
    )


def _run_poc(
    poc_path: Path, *, work_dir: Path, image: str, no_sandbox: bool
) -> SandboxResult:
    if no_sandbox:
        # Local execution — useful when Docker is unavailable but the user
        # has accepted the risk. Same signal/exit-code conventions apply.
        try:
            proc = subprocess.run(  # noqa: S603 - argv-only, no shell
                ["python3", str(poc_path)],  # noqa: S607
                capture_output=True,
                text=True,
                cwd=work_dir,
                timeout=60,
                check=False,
            )
            return SandboxResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_sec=0.0,
                signal_seen=DEFAULT_SIGNAL in proc.stdout,
                timed_out=False,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                exit_code=124, stdout="", stderr="", duration_sec=60.0,
                signal_seen=False, timed_out=True,
            )
    return run_in_sandbox(
        ["python3", "poc.py"], image=image, work_dir=work_dir
    )


def run_validator(
    state: RunState,
    *,
    repo_dir: Path,
    llm: LLMConfig | None = None,
    no_sandbox: bool = False,
) -> Path:
    """Drive the validator skill, execute each PoC, update finding statuses.

    Returns the path to the validation_log.md.
    """
    findings_dir = state.run_dir / "findings"
    if not findings_dir.is_dir():
        raise FileNotFoundError(f"no findings/ at {findings_dir}")

    state.phase = "validate"
    save(state)

    # Drive the validator skill — produces poc.py per finding.
    effective = llm or LLMConfig(provider=state.llm_provider, model=state.llm_model)
    if is_available(effective.provider):
        cmd_script = write_llm_cmd_script(state.run_dir / ".llm-cmd-validate.sh", effective)
        env = os.environ.copy()
        env["AI_CODESCAN_RUN_DIR"] = str(state.run_dir)
        env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
        env["AI_CODESCAN_LLM_CMD"] = str(cmd_script)
        subprocess.run(  # noqa: S603 - argv-only, no shell
            ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
            env=env,
            check=False,  # one PoC failure should not abort the rest
        )
    _ = repo_dir  # reserved for future passes

    # Execute every PoC the skill produced.
    log_rows: list[str] = []
    for finding_path in sorted(findings_dir.glob("*.md")):
        finding = parse_finding(finding_path.read_text(encoding="utf-8"))
        if finding.status != "unverified":
            continue
        poc_path = state.run_dir / "sandbox" / finding.finding_id / "poc.py"
        if not poc_path.is_file():
            continue
        try:
            result = _run_poc(
                poc_path,
                work_dir=poc_path.parent,
                image=image_for_lang("python"),
                no_sandbox=no_sandbox,
            )
        except SandboxUnavailableError:
            log_rows.append(
                f"| {finding.finding_id} | sandbox-unavailable | -- | -- | -- |"
            )
            continue
        new_status = cast(Status, _flip_status(result))
        updated = Finding(
            finding_id=finding.finding_id,
            nomination_id=finding.nomination_id,
            flow_id=finding.flow_id,
            cwe=finding.cwe,
            status=new_status,
            title=finding.title,
            body=finding.body,
        )
        finding_path.write_text(render_finding(updated), encoding="utf-8")
        log_rows.append(_validation_log_row(finding.finding_id, new_status, result))

    log_path = state.run_dir / "validation_log.md"
    header = (
        "# Validation log\n\n"
        "| finding | status | exit | signal | timed_out |\n"
        "|---|---|---|---|---|\n"
    )
    log_path.write_text(header + "\n".join(log_rows) + "\n", encoding="utf-8")
    return log_path
