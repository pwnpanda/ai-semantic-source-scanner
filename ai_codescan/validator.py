"""Drive the validator skill end-to-end and execute PoCs in the sandbox."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, cast

from ai_codescan.findings.model import Finding, Status, parse_finding, render_finding
from ai_codescan.llm import LLMConfig, is_available
from ai_codescan.nominator import write_llm_cmd_script
from ai_codescan.runs.state import RunState, save
from ai_codescan.sandbox import (
    DEFAULT_SIGNAL,
    LanguageProfile,
    SandboxResult,
    SandboxUnavailableError,
    UnsupportedPocLanguageError,
    configured_runtime,
    profile_for_extension,
    run_in_sandbox,
)
from ai_codescan.taxonomy.loader import list_classes

SKILL_DIR = Path(__file__).resolve().parent / "skills" / "validator"

_VERDICT_RE = re.compile(r"\{[^{}]*\"verdict\"[^{}]*\}")


def _parse_verdict(stdout: str) -> dict[str, Any] | None:
    """Return the last JSON verdict block from ``stdout`` if present.

    PoCs may emit a final line like ``{"verdict": "vulnerable",
    "evidence": [...], "confidence": 0.9}``. Returns ``None`` if absent or
    unparseable.
    """
    for match in reversed(_VERDICT_RE.findall(stdout or "")):
        try:
            data = json.loads(match)
        except (json.JSONDecodeError, ValueError):
            continue
        verdict = str(data.get("verdict", "")).lower()
        if verdict in {"vulnerable", "not_vulnerable", "inconclusive"}:
            return data
    return None


def _flip_status(result: SandboxResult) -> tuple[str, dict[str, Any] | None]:
    """Combine multiple verdict signals into a status.

    Priority order (any signal wins, ties go to the strongest claim):
    1. Structured JSON verdict in stdout (preferred — explicit + confidence).
    2. ``OK_VULN`` magic string (legacy stdout signal).
    3. Exit code + timeout fallback.
    """
    parsed = _parse_verdict(result.stdout)
    if parsed:
        verdict = str(parsed["verdict"]).lower()
        if verdict == "vulnerable":
            return "verified", parsed
        if verdict == "not_vulnerable":
            return "rejected", parsed
        return "poc_inconclusive", parsed
    if result.signal_seen:
        return "verified", None
    if result.exit_code == 0 and not result.timed_out:
        return "rejected", None
    return "poc_inconclusive", None


def _validation_log_row(
    finding_id: str,
    status: str,
    result: SandboxResult,
    verdict: dict[str, Any] | None,
) -> str:
    confidence = ""
    if verdict and "confidence" in verdict:
        confidence = f" conf={verdict['confidence']}"
    evidence_count = len(verdict.get("evidence", [])) if verdict else 0
    return (
        f"| {finding_id} | {status} | exit={result.exit_code} "
        f"| signal={'y' if result.signal_seen else 'n'} "
        f"| timed_out={'y' if result.timed_out else 'n'} "
        f"| evidence={evidence_count}{confidence} |"
    )


def _hints_for_cwe(cwe: str | None) -> list[str]:
    """Return validation_hints from the taxonomy for the given CWE, if any."""
    if not cwe:
        return []
    cwe_norm = cwe.upper().replace(" ", "")
    for klass in list_classes():
        if any(c.upper().replace(" ", "") == cwe_norm for c in klass.cwes):
            return list(klass.validation_hints)
    return []


def _local_argv(profile: LanguageProfile, poc_path: Path) -> list[str]:
    """Argv to execute the PoC locally (no container)."""
    interpreter_parts = profile.interpreter.split()
    return [*interpreter_parts, str(poc_path)]


def _container_argv(profile: LanguageProfile, poc_path: Path) -> list[str]:
    """Argv to execute the PoC inside the container at /work/<filename>."""
    interpreter_parts = profile.interpreter.split()
    return [*interpreter_parts, poc_path.name]


def _run_poc(
    poc_path: Path,
    *,
    work_dir: Path,
    profile: LanguageProfile,
    no_sandbox: bool,
) -> SandboxResult:
    if no_sandbox:
        # Local execution — used when runtime=none or the user passes --no-sandbox.
        # Same signal/exit-code conventions as the container path. Only Python
        # is supported here; we can't assume node/go/ruby/etc. are on PATH.
        if not profile.local_supported:
            raise SandboxUnavailableError(
                f"PoC language {profile.name!r} requires a container runtime; "
                "install docker or podman, or rewrite the PoC in Python."
            )
        argv = _local_argv(profile, poc_path)
        try:
            proc = subprocess.run(  # noqa: S603 - argv-only, no shell
                argv,  # noqa: S607 - first arg is a literal interpreter name
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
                runtime="none",
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                exit_code=124,
                stdout="",
                stderr="",
                duration_sec=60.0,
                signal_seen=False,
                timed_out=True,
                runtime="none",
            )
    return run_in_sandbox(
        _container_argv(profile, poc_path),
        image=profile.image,
        work_dir=work_dir,
    )


def run_validator(  # noqa: PLR0912, PLR0915 - orchestrator inherently combines several stages
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

    # Drive the validator skill — produces poc.<ext> per finding.
    effective = llm or LLMConfig(provider=state.llm_provider, model=state.llm_model)
    if is_available(effective.provider):
        cmd_script = write_llm_cmd_script(state.run_dir / ".llm-cmd-validate.sh", effective)
        env = os.environ.copy()
        env["AI_CODESCAN_RUN_DIR"] = str(state.run_dir)
        env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
        env["AI_CODESCAN_LLM_CMD"] = str(cmd_script)
        env["CLAUDE_NO_AUTO_REGISTER"] = "1"
        # Stage validation hints per finding so the skill can read them.
        hints_dir = state.run_dir / "validation_hints"
        hints_dir.mkdir(exist_ok=True)
        for fpath in sorted((state.run_dir / "findings").glob("*.md")):
            f = parse_finding(fpath.read_text(encoding="utf-8"))
            hints = _hints_for_cwe(f.cwe)
            if hints:
                (hints_dir / f"{f.finding_id}.md").write_text(
                    "# Validation hints (per-CWE rubric)\n\n"
                    + "\n".join(f"- {h}" for h in hints)
                    + "\n",
                    encoding="utf-8",
                )
        subprocess.run(  # noqa: S603 - argv-only, no shell
            ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
            env=env,
            check=False,  # one PoC failure should not abort the rest
        )
    _ = repo_dir  # reserved for future passes

    # If runtime=none in user_config, force no_sandbox unless the caller already did.
    if not no_sandbox and configured_runtime() == "none":
        no_sandbox = True

    # Execute every PoC the skill produced.
    log_rows: list[str] = []
    for finding_path in sorted(findings_dir.glob("*.md")):
        finding = parse_finding(finding_path.read_text(encoding="utf-8"))
        if finding.status != "unverified":
            continue
        # Look for poc.<ext> for any supported extension; fall back to poc.py.
        sandbox_dir = state.run_dir / "sandbox" / finding.finding_id
        if not sandbox_dir.is_dir():
            continue
        poc_path = next(
            (p for p in sandbox_dir.glob("poc.*") if p.is_file()),
            None,
        )
        if poc_path is None:
            continue
        # Extension drives the language profile. Unknown extensions are
        # logged and skipped — the LLM picked something we don't support.
        try:
            profile = profile_for_extension(poc_path.suffix)
        except UnsupportedPocLanguageError:
            log_rows.append(
                f"| {finding.finding_id} | unsupported-poc-language "
                f"({poc_path.suffix or 'no-extension'}) | -- | -- | -- |"
            )
            continue
        try:
            result = _run_poc(
                poc_path,
                work_dir=poc_path.parent,
                profile=profile,
                no_sandbox=no_sandbox,
            )
        except SandboxUnavailableError:
            log_rows.append(f"| {finding.finding_id} | sandbox-unavailable | -- | -- | -- |")
            continue
        flipped, verdict = _flip_status(result)
        new_status = cast(Status, flipped)
        # If the JSON verdict carried evidence, append it to the finding body.
        body = finding.body
        if verdict and verdict.get("evidence"):
            body = body.rstrip() + "\n\n## Validation evidence\n\n"
            body += "\n".join(f"- {e}" for e in verdict["evidence"]) + "\n"
            if "confidence" in verdict:
                body += f"\n*Confidence: {verdict['confidence']}*\n"
        updated = Finding(
            finding_id=finding.finding_id,
            nomination_id=finding.nomination_id,
            flow_id=finding.flow_id,
            cwe=finding.cwe,
            status=new_status,
            title=finding.title,
            body=body,
        )
        finding_path.write_text(render_finding(updated), encoding="utf-8")
        log_rows.append(_validation_log_row(finding.finding_id, new_status, result, verdict))

    log_path = state.run_dir / "validation_log.md"
    header = (
        "# Validation log\n\n"
        "| finding | status | exit | signal | timed_out | evidence |\n"
        "|---|---|---|---|---|---|\n"
    )
    log_path.write_text(header + "\n".join(log_rows) + "\n", encoding="utf-8")
    return log_path
