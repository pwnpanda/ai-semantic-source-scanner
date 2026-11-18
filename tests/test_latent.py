"""Tests for latent finding artifacts."""

import json
from pathlib import Path

from ai_codescan.findings.model import Finding, render_finding
from ai_codescan.latent import collect_latent_findings, write_latent_artifacts


def _write_finding(path: Path, finding: Finding) -> None:
    path.write_text(render_finding(finding), encoding="utf-8")


def test_latent_artifacts_include_unverified_security_primitive(tmp_path: Path) -> None:
    findings_dir = tmp_path / "run" / "findings"
    findings_dir.mkdir(parents=True)
    finding = Finding(
        finding_id="F-ssrf",
        nomination_id="N-ssrf",
        flow_id="flow-ssrf",
        cwe="CWE-918",
        status="unverified",
        title="Same-origin server request primitive",
        body="The request can reach another path on the configured host.",
        exploitability="latent",
        unmet_prerequisites=("A sensitive same-origin endpoint becomes reachable.",),
    )
    _write_finding(findings_dir / "F-ssrf.md", finding)

    result = write_latent_artifacts(
        findings_dir=findings_dir,
        run_dir=tmp_path / "run",
        report_dir=tmp_path / "report",
    )

    assert result.findings == (finding,)
    assert "Same-origin server request" in result.report_path.read_text(encoding="utf-8")
    row = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert row["exploitability"] == "latent"
    assert row["unmet_prerequisites"] == ["A sensitive same-origin endpoint becomes reachable."]


def test_rejected_or_nonlatent_findings_are_not_in_latent_report(tmp_path: Path) -> None:
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir()
    base = {
        "nomination_id": "N-1",
        "flow_id": "flow-1",
        "cwe": "CWE-918",
        "title": "Request primitive",
        "body": "Body.",
    }
    _write_finding(
        findings_dir / "F-rejected.md",
        Finding(
            finding_id="F-rejected",
            status="rejected",
            exploitability="latent",
            unmet_prerequisites=("A sensitive same-origin endpoint becomes reachable.",),
            **base,
        ),
    )
    _write_finding(
        findings_dir / "F-demonstrated.md",
        Finding(
            finding_id="F-demonstrated",
            status="verified",
            exploitability="demonstrated",
            **base,
        ),
    )

    assert collect_latent_findings(findings_dir) == []
