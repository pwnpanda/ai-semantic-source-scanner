"""Surface findings whose current impact depends on unmet prerequisites."""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path

from ai_codescan.findings.model import Finding, parse_finding


@dataclass(frozen=True, slots=True)
class LatentRunResult:
    findings: tuple[Finding, ...]
    json_path: Path
    markdown_path: Path
    report_path: Path


def collect_latent_findings(findings_dir: Path) -> list[Finding]:
    """Return non-rejected findings with an explicit latent exploitability state."""
    findings: list[Finding] = []
    for path in sorted(findings_dir.glob("*.md")):
        markdown = path.read_text(encoding="utf-8")
        if not markdown.startswith("---\n"):
            continue
        finding = parse_finding(markdown)
        if finding.exploitability == "latent" and finding.status != "rejected":
            findings.append(finding)
    return findings


def render_latent_report(findings: list[Finding]) -> str:
    """Render latent security primitives without claiming current exploitation."""
    lines = [
        "# Latent findings",
        "",
        "A latent finding describes a security primitive with unmet impact prerequisites.",
        "It remains visible because future changes can satisfy those prerequisites.",
        "",
    ]
    if not findings:
        lines.append("No latent findings were recorded.")
        return "\n".join(lines) + "\n"
    for finding in findings:
        lines.extend(
            [
                f"## {finding.finding_id}: {finding.title}",
                "",
                f"- Validation status: `{finding.status}`",
                f"- CWE: `{finding.cwe or 'unknown'}`",
                "- Current exploitability: `latent`",
                "- Unmet prerequisites:",
            ]
        )
        lines.extend(f"  - {item}" for item in finding.unmet_prerequisites)
        lines.extend(["", finding.body.strip(), ""])
    return "\n".join(lines).rstrip() + "\n"


def write_latent_artifacts(
    *,
    findings_dir: Path,
    run_dir: Path,
    report_dir: Path,
) -> LatentRunResult:
    """Write run JSONL and Markdown files plus the external report copy."""
    findings = collect_latent_findings(findings_dir)
    json_path = run_dir / "latent-findings.jsonl"
    markdown_path = run_dir / "latent-findings.md"
    json_path.write_text(
        "".join(json.dumps(asdict(finding), sort_keys=True) + "\n" for finding in findings),
        encoding="utf-8",
    )
    markdown_path.write_text(render_latent_report(findings), encoding="utf-8")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "latent-findings.md"
    shutil.copyfile(markdown_path, report_path)
    return LatentRunResult(tuple(findings), json_path, markdown_path, report_path)
