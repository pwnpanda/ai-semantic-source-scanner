"""Render verified findings as bug-bounty-ready markdown reports."""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb

from ai_codescan.evidence import EvidenceBundle
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
    "CWE-532": "low",
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
    "CWE-532": "sensitive-logging",
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

# Severity tiers ordered from weakest to strongest. The integer ranks are
# private to `_apply_factor_deltas` — callers see the string labels.
_SEVERITY_RANKS: list[str] = ["informational", "low", "medium", "high", "critical"]

# Score-factor adjustments. Each entry is `(factor_name, value_threshold, delta)`:
# the delta is applied when the factor is present and its `value` is on the
# "trigger" side of the threshold. Strong-mitigation factors use a negative
# threshold; engine-consensus / entrypoint-proximity always trigger on
# presence. Magnitudes are eyeball-tuned (Phase 2) and tracked in REVIEW.md.
_FACTOR_DELTAS: list[tuple[str, float, int]] = [
    ("engine_consensus", 0.0, +1),
    ("entrypoint_proximity", 0.0, +1),
    ("mitigation_signal", -0.15, -1),
    ("colocation_fallback", -0.0, -1),
    ("overlap_with_deterministic", -0.15, -1),
    ("low_signal_path", -0.0, -1),
]


def _severity_for(cwe: str | None) -> str:
    return _CWE_SEVERITY.get(cwe or "", "informational")


def _apply_factor_deltas(base: str, score_factors: list[dict[str, Any]] | None) -> str:
    """Bump or drop severity based on score factors.

    Each matching factor shifts severity by ±1 tier; total is clamped to the
    `_SEVERITY_RANKS` range. Empty/None factors → static base severity.
    """
    if not score_factors:
        return base
    rank = _SEVERITY_RANKS.index(base) if base in _SEVERITY_RANKS else 0
    delta_total = 0
    for factor in score_factors:
        if not isinstance(factor, dict):
            continue
        name = str(factor.get("name") or "")
        try:
            value = float(factor.get("value") or 0.0)
        except (TypeError, ValueError):
            value = 0.0
        for fname, threshold, delta in _FACTOR_DELTAS:
            if name != fname:
                continue
            # Positive deltas trigger on presence; negative deltas trigger
            # only when the factor value is at or below the threshold so
            # weak mitigation signals don't move severity.
            if delta > 0 or value <= threshold:
                delta_total += delta
    final_rank = max(0, min(len(_SEVERITY_RANKS) - 1, rank + delta_total))
    return _SEVERITY_RANKS[final_rank]


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


def derive_meta(
    finding: Finding,
    *,
    today: _dt.date | None = None,
    score_factors: list[dict[str, Any]] | None = None,
    llm_judge: SeverityJudge | None = None,
) -> ReportMeta:
    """Pick severity, component and vuln-class for a finding.

    Severity derivation, in priority order:

    1. If ``llm_judge`` is provided AND returns a valid tier string, use it.
       The judge gets the CWE, vuln_class, finding body, and the score
       factors so it can reason about context (Phase 7 LLM polish).
    2. Else fall back to the multi-factor calculation from Phase 2:
       base CWE severity + ±1 tier per matching score factor, clamped.

    The judge is a callable, not a hard-wired LLM CLI, so callers can mock
    it for testing. Live LLM verification requires the user's CLI to be
    configured; see `severity_judge.run_judge` for the default
    implementation that shells out to the configured LLM.
    """
    base_severity = _severity_for(finding.cwe)
    severity = _apply_factor_deltas(base_severity, score_factors)
    if llm_judge is not None:
        try:
            judged = llm_judge(
                cwe=finding.cwe or "",
                vuln_class=_vuln_class_for(finding.cwe),
                body=finding.body,
                base_severity=severity,
                score_factors=list(score_factors or []),
            )
        except Exception:  # noqa: BLE001 - LLM failure must never break reporting
            judged = None
        if judged and judged in _SEVERITY_RANKS:
            severity = judged
    return ReportMeta(
        severity=severity,
        component=_component_from_finding(finding),
        vuln_class=_vuln_class_for(finding.cwe),
        date=(today or _dt.date.today()).isoformat(),
    )


# Type alias for the optional LLM severity judge. The callable receives
# enough context to make a meaningful tier decision; it must return one of
# the strings in _SEVERITY_RANKS or None (fall back to deterministic).
from typing import Protocol  # noqa: PLC0415, E402 - kept colocated with the type alias


class SeverityJudge(Protocol):
    def __call__(
        self,
        *,
        cwe: str,
        vuln_class: str,
        body: str,
        base_severity: str,
        score_factors: list[dict[str, Any]],
    ) -> str | None: ...


_FILENAME_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(value: str) -> str:
    """Reduce a label to a filename-safe slug.

    Component names are derived from finding prose, so they pick up whatever
    punctuation surrounded the path — backticks, parentheses and quotes have
    all shown up. Those make the resulting files awkward to quote in a shell
    and invalid on Windows, so collapse anything outside ``[A-Za-z0-9._-]``.
    """
    cleaned = _FILENAME_UNSAFE_RE.sub("-", value).strip("-.")
    return cleaned or "unknown"


def report_filename(meta: ReportMeta) -> str:
    """Bug-bounty-style filename: ``YYYY-MM-DD--<sev>--<class>--<component>.md``."""
    return (
        f"{_slug(meta.date)}--{_slug(meta.severity)}"
        f"--{_slug(meta.vuln_class)}--{_slug(meta.component)}.md"
    )


def _render_bundle_evidence(bundle: EvidenceBundle | None) -> str:
    if bundle is None:
        return ""
    # Stream B (AI-discovered) candidates have no static flow behind them, so
    # engine/score/sink are legitimately empty. Emitting them as empty
    # backticks reads like missing data; drop the rows that have no value.
    score = (
        f"{bundle.score} ({bundle.score_label})"
        if bundle.score is not None and bundle.score_label
        else (str(bundle.score) if bundle.score is not None else "")
    )
    sink = " ".join(part for part in (bundle.sink_name, bundle.sink_class) if part)
    source = " ".join(part for part in (bundle.source_loc, bundle.source_name) if part)
    rows: list[tuple[str, str]] = [
        ("Stream", bundle.stream or ""),
        ("Engine", bundle.engine or ""),
        ("Confidence", bundle.confidence or ""),
        ("Score", score),
        ("Source", source),
        ("Sink", sink),
        ("Parameterization", bundle.parameterization or ""),
    ]
    lines = ["## Scanner Evidence", ""]
    lines.extend(f"- {label}: {value}" for label, value in rows if value)
    lines.append("")
    if bundle.score_factors:
        lines.extend(["### Score Factors", ""])
        for factor in bundle.score_factors:
            lines.append(
                f"- `{factor.get('name', '')}` {factor.get('value', '')}: "
                f"{factor.get('reason', '')}"
            )
        lines.append("")
    if bundle.mitigations:
        lines.extend(["### Mitigation Signals", ""])
        for signal in bundle.mitigations:
            lines.append(
                f"- `{signal.get('kind', '')}` {signal.get('confidence', '')}: "
                f"{signal.get('reason', '')}"
            )
        lines.append("")
    if bundle.entrypoints:
        lines.extend(["### Entrypoints", ""])
        for entrypoint in bundle.entrypoints:
            lines.append(
                f"- `{entrypoint.kind}` {entrypoint.file}:{entrypoint.line} {entrypoint.signature}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n\n"


def _render_verdict(verdict: dict[str, Any] | None) -> str:
    if not verdict:
        return ""
    return (
        "## Review Verdict\n\n"
        f"- Verdict: `{verdict.get('verdict', '')}`\n"
        f"- Confidence: `{verdict.get('confidence', '')}`\n"
        f"- Reviewer: `{verdict.get('reviewer', '')}`\n\n"
    )


def summary_from_body(body: str, *, fallback: str) -> str:
    """First prose paragraph of a finding body.

    Analyser output opens with its own ``## Summary`` heading, so taking the
    body's first line yields that heading verbatim and the report renders
    ``## Summary`` twice with no prose. Skip headings, blank lines and code
    fences, and return the first real paragraph instead.
    """
    paragraph: list[str] = []
    in_fence = False
    for raw in body.splitlines():
        line = raw.strip()
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or line.startswith("#"):
            continue
        if not line:
            if paragraph:
                break
            continue
        paragraph.append(line)
    return " ".join(paragraph) if paragraph else fallback


def render_report(
    finding: Finding,
    *,
    meta: ReportMeta | None = None,
    bundle: EvidenceBundle | None = None,
    review_verdict: dict[str, Any] | None = None,
) -> str:
    """Render the markdown report body."""
    m = meta or derive_meta(finding)
    cwe = finding.cwe or "unknown"
    enriched = _render_bundle_evidence(bundle) + _render_verdict(review_verdict)
    summary = summary_from_body(finding.body, fallback=finding.title)
    return (
        f"# {finding.title}\n\n"
        f"## Summary\n\n{summary}\n\n"
        f"## Severity\n\n- Rating: **{m.severity}**\n- CWE: {cwe}\n- Vuln class: {m.vuln_class}\n\n"
        "## Environment\n\n_Document target version, OS, and configuration here._\n\n"
        "## Prerequisites\n\n_List any setup needed to reproduce._\n\n"
        "## Reproduction Steps\n\n_Numbered, exact commands._\n\n"
        "## Expected vs Actual\n\n_What should happen vs what does._\n\n"
        f"{enriched}"
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
    bundle: EvidenceBundle | None = None,
    review_verdict: dict[str, Any] | None = None,
) -> Path:
    """Write the report to ``report_dir`` using the standard filename. Returns the path."""
    factors = list(bundle.score_factors) if bundle is not None else None
    meta = derive_meta(finding, today=today, score_factors=factors)
    report_dir.mkdir(parents=True, exist_ok=True)
    target = report_dir / report_filename(meta)
    target.write_text(
        render_report(finding, meta=meta, bundle=bundle, review_verdict=review_verdict),
        encoding="utf-8",
    )
    return target


def render_candidate_audit(conn: duckdb.DuckDBPyConnection) -> str:
    """Render scored candidates that were not necessarily promoted to findings."""
    has_scores = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'candidate_scores'"
    ).fetchone()
    if not has_scores or int(has_scores[0]) == 0:
        return "# Candidate Audit\n\nNo scored candidates.\n"
    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info('candidate_scores')").fetchall()
    }
    bucket_expr = "processing_bucket" if "processing_bucket" in columns else "label"
    rows = conn.execute(
        f"""
        SELECT candidate_id, label, {bucket_expr}, ROUND(score, 3), stream, flow_id
        FROM candidate_scores
        ORDER BY score DESC, candidate_id
        """  # noqa: S608 - bucket_expr is selected from known column names above.
    ).fetchall()
    lines = [
        "# Candidate Audit",
        "",
        "| Candidate | Label | Bucket | Score | Stream | Flow |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for candidate_id, label, bucket, score, stream, flow_id in rows:
        lines.append(
            f"| `{candidate_id}` | {label or ''} | {bucket or ''} | "
            f"{score if score is not None else ''} | {stream or ''} | `{flow_id or ''}` |"
        )
    return "\n".join(lines) + "\n"


def write_candidate_audit(conn: duckdb.DuckDBPyConnection, *, report_dir: Path) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    target = report_dir / "candidate-audit.md"
    target.write_text(render_candidate_audit(conn), encoding="utf-8")
    return target
