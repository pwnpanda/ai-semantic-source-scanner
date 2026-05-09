"""Render verified findings as bug-bounty-ready markdown reports."""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass
from pathlib import Path

from ai_codescan.findings.model import Finding


@dataclass(frozen=True, slots=True)
class ReportMeta:
    severity: str  # critical | high | medium | low | informational
    component: str
    vuln_class: str
    date: str  # YYYY-MM-DD


_CWE_SEVERITY: dict[str, str] = {
    # SQL/cmd/code injection — typically critical-to-high
    "CWE-89": "critical",
    "CWE-78": "critical",
    "CWE-94": "critical",
    "CWE-502": "critical",
    "CWE-611": "high",
    "CWE-1336": "high",
    "CWE-918": "high",
    "CWE-79": "high",
    "CWE-22": "high",
    "CWE-98": "high",
    "CWE-90": "high",
    "CWE-639": "medium",
    "CWE-862": "medium",
    "CWE-915": "medium",
    "CWE-601": "medium",
    "CWE-942": "medium",
    "CWE-93": "medium",
    "CWE-1321": "medium",
    "CWE-1333": "low",
    "CWE-200": "low",
    "CWE-352": "medium",
    "CWE-287": "high",
    "CWE-345": "high",
    "CWE-347": "high",
    "CWE-384": "medium",
    "CWE-444": "high",
    "CWE-330": "low",
    "CWE-338": "medium",
    "CWE-327": "medium",
    "CWE-328": "medium",
    "CWE-1427": "medium",
    "CWE-943": "high",
}

_CWE_VULN_CLASS: dict[str, str] = {
    "CWE-89": "sqli",
    "CWE-78": "cmdi",
    "CWE-94": "code-injection",
    "CWE-79": "xss",
    "CWE-22": "path-traversal",
    "CWE-918": "ssrf",
    "CWE-352": "csrf",
    "CWE-639": "idor",
    "CWE-611": "xxe",
    "CWE-502": "unsafe-deserialization",
    "CWE-1336": "ssti",
    "CWE-1321": "prototype-pollution",
    "CWE-1333": "redos",
    "CWE-601": "open-redirect",
    "CWE-942": "cors-misconfig",
    "CWE-915": "mass-assignment",
    "CWE-862": "bfla",
    "CWE-200": "info-disclosure",
    "CWE-943": "nosqli",
    "CWE-90": "ldap-injection",
    "CWE-93": "crlf-injection",
    "CWE-98": "file-inclusion",
    "CWE-287": "auth-bypass",
    "CWE-345": "jwt-misuse",
    "CWE-347": "jwt-misuse",
    "CWE-384": "session-fixation",
    "CWE-444": "request-smuggling",
    "CWE-1427": "prompt-injection",
    "CWE-330": "insecure-random",
    "CWE-338": "insecure-random",
    "CWE-327": "weak-crypto",
    "CWE-328": "weak-crypto",
}

_PATH_LINE_RE = re.compile(r"(?P<path>[^\s:]+\.(?:ts|tsx|js|jsx|mjs|cjs|html|py))(?::\d+)?")


def _severity_for(cwe: str | None) -> str:
    return _CWE_SEVERITY.get(cwe or "", "informational")


def _vuln_class_for(cwe: str | None) -> str:
    return _CWE_VULN_CLASS.get(cwe or "", "unknown")


def _component_from_finding(finding: Finding) -> str:
    """Best-effort component name from the finding body's first file path or title."""
    m = _PATH_LINE_RE.search(finding.body) or _PATH_LINE_RE.search(finding.title)
    if not m:
        return "unknown"
    path = m.group("path")
    parts = Path(path).parts
    # Drop trailing .ext for the component label.
    leaf = Path(parts[-1]).stem if parts else "unknown"
    return leaf or "unknown"


def derive_meta(finding: Finding, *, today: _dt.date | None = None) -> ReportMeta:
    """Pick severity, component and vuln-class for a finding."""
    return ReportMeta(
        severity=_severity_for(finding.cwe),
        component=_component_from_finding(finding),
        vuln_class=_vuln_class_for(finding.cwe),
        date=(today or _dt.date.today()).isoformat(),
    )


def report_filename(meta: ReportMeta) -> str:
    """Bug-bounty-style filename: ``YYYY-MM-DD--<sev>--<class>--<component>.md``."""
    return f"{meta.date}--{meta.severity}--{meta.vuln_class}--{meta.component}.md"


def render_report(finding: Finding, *, meta: ReportMeta | None = None) -> str:
    """Render the markdown report body."""
    m = meta or derive_meta(finding)
    cwe = finding.cwe or "unknown"
    return (
        f"# {finding.title}\n\n"
        f"## Summary\n\n{finding.body.split(chr(10), 1)[0] if finding.body else finding.title}\n\n"
        f"## Severity\n\n- Rating: **{m.severity}**\n- CWE: {cwe}\n- Vuln class: {m.vuln_class}\n\n"
        "## Environment\n\n_Document target version, OS, and configuration here._\n\n"
        "## Prerequisites\n\n_List any setup needed to reproduce._\n\n"
        "## Reproduction Steps\n\n_Numbered, exact commands._\n\n"
        "## Expected vs Actual\n\n_What should happen vs what does._\n\n"
        f"## Evidence\n\n{finding.body}\n\n"
        "## Impact\n\n_Concrete outcome + blast radius._\n\n"
        "## Remediation\n\n_Concrete code change._\n\n"
        f"## References\n\n- finding_id: `{finding.finding_id}`\n"
        f"- nomination_id: `{finding.nomination_id}`\n"
        f"- flow_id: `{finding.flow_id}`\n"
    )


def write_report(
    finding: Finding,
    *,
    report_dir: Path,
    today: _dt.date | None = None,
) -> Path:
    """Write the report to ``report_dir`` using the standard filename. Returns the path."""
    meta = derive_meta(finding, today=today)
    report_dir.mkdir(parents=True, exist_ok=True)
    target = report_dir / report_filename(meta)
    target.write_text(render_report(finding, meta=meta), encoding="utf-8")
    return target
