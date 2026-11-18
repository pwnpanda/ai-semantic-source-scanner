"""Drive the validator skill end-to-end and execute PoCs in the sandbox."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import duckdb

from ai_codescan.findings.model import Finding, Status, parse_finding, render_finding
from ai_codescan.lineage import refresh_candidate_lineage
from ai_codescan.llm import LLMConfig, is_available
from ai_codescan.nominator import write_llm_cmd_script
from ai_codescan.review_cache import build_llm_context_fingerprint
from ai_codescan.review_verdicts import sync_review_verdicts
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
_LEGACY_BENIGN_RE = re.compile(r"(?m)^\s*BENIGN\s*$")
_VALIDATABLE_STATUSES = frozenset({"unverified", "poc_inconclusive"})
_EVIDENCE_START = "<!-- ai-codescan-validation-evidence:start -->"
_EVIDENCE_END = "<!-- ai-codescan-validation-evidence:end -->"


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


def _verdict_evidence(verdict: dict[str, Any]) -> list[str]:
    raw_evidence = verdict.get("evidence")
    if not isinstance(raw_evidence, list):
        return []
    return [item.strip() for item in raw_evidence if isinstance(item, str) and item.strip()]


def _structured_verdict_status(verdict: dict[str, Any]) -> str:
    verdict_name = str(verdict["verdict"]).lower()
    if verdict_name == "vulnerable":
        return "verified"
    if verdict_name != "not_vulnerable":
        return "poc_inconclusive"
    return "rejected" if _verdict_evidence(verdict) else "poc_inconclusive"


def _flip_status(result: SandboxResult) -> tuple[str, dict[str, Any] | None]:
    """Combine multiple verdict signals into a status.

    Priority order (any signal wins, ties go to the strongest claim):
    1. Structured JSON verdict in stdout (preferred — explicit + confidence).
    2. ``OK_VULN`` magic string (legacy stdout signal).
    3. Exit code + timeout fallback.
    """
    parsed = _parse_verdict(result.stdout)
    if parsed:
        return _structured_verdict_status(parsed), parsed
    if result.signal_seen:
        return "verified", None
    if result.exit_code == 0 and not result.timed_out:
        if _LEGACY_BENIGN_RE.search(result.stdout):
            return "rejected", None
        return "poc_inconclusive", None
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


def _body_with_validation_evidence(body: str, verdict: dict[str, Any] | None) -> str:
    if not verdict or not (evidence_items := _verdict_evidence(verdict)):
        return body
    evidence = "\n".join(f"- {item}" for item in evidence_items)
    confidence = ""
    if "confidence" in verdict:
        confidence = f"\n\n*Confidence: {verdict['confidence']}*"
    block = (
        f"{_EVIDENCE_START}\n\n## Validation evidence\n\n{evidence}{confidence}\n\n{_EVIDENCE_END}"
    )
    if _EVIDENCE_START not in body:
        return body.rstrip() + "\n\n" + block + "\n"
    prefix, _start, remainder = body.partition(_EVIDENCE_START)
    _old, end, suffix = remainder.partition(_EVIDENCE_END)
    if not end:
        return prefix.rstrip() + "\n\n" + block + "\n"
    suffix = suffix.lstrip("\n")
    return prefix.rstrip() + "\n\n" + block + ("\n\n" + suffix if suffix else "\n")


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
    read_only_mounts: Sequence[tuple[Path, Path]] = (),
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
        read_only_mounts=read_only_mounts,
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
        env["AI_CODESCAN_SOURCE_ROOT"] = str(repo_dir / "source")
        env["AI_CODESCAN_LLM_CONTEXT"] = build_llm_context_fingerprint(
            effective,
            source_root=repo_dir / "source",
        )
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
        env["AI_CODESCAN_HINTS_DIR"] = str(hints_dir)
        subprocess.run(  # noqa: S603 - argv-only, no shell
            ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
            env=env,
            check=True,
        )
    _ = repo_dir  # reserved for future passes

    # If runtime=none in user_config, force no_sandbox unless the caller already did.
    if not no_sandbox and configured_runtime() == "none":
        no_sandbox = True

    # Execute every PoC the skill produced.
    log_rows: list[str] = []
    for finding_path in sorted(findings_dir.glob("*.md")):
        finding = parse_finding(finding_path.read_text(encoding="utf-8"))
        if finding.status not in _VALIDATABLE_STATUSES:
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
            source_root = repo_dir / "source"
            result = _run_poc(
                poc_path,
                work_dir=poc_path.parent,
                profile=profile,
                no_sandbox=no_sandbox,
                read_only_mounts=(
                    (source_root, source_root),
                    (state.run_dir, state.run_dir),
                ),
            )
        except SandboxUnavailableError:
            log_rows.append(f"| {finding.finding_id} | sandbox-unavailable | -- | -- | -- |")
            continue
        flipped, verdict = _flip_status(result)
        new_status = cast(Status, flipped)
        body = _body_with_validation_evidence(finding.body, verdict)
        updated = Finding(
            finding_id=finding.finding_id,
            nomination_id=finding.nomination_id,
            flow_id=finding.flow_id,
            cwe=finding.cwe,
            status=new_status,
            title=finding.title,
            body=body,
            candidate_id=finding.candidate_id,
            exploitability=finding.exploitability,
            unmet_prerequisites=finding.unmet_prerequisites,
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
    db_path = repo_dir / "index.duckdb"
    if db_path.is_file():
        conn = duckdb.connect(str(db_path))
        try:
            sync_review_verdicts(conn, findings_dir, nomination_prefix="N-")
        finally:
            conn.close()
    refresh_candidate_lineage(state.run_dir)
    return log_path
