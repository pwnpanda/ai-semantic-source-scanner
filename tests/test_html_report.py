"""Tests for ai_codescan.html_report — the self-contained HTML report."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb

from ai_codescan.findings.model import Finding
from ai_codescan.html_report import render_html_report
from ai_codescan.index.duckdb_schema import apply_schema


def _finding(fid: str = "F-1", cwe: str = "CWE-89", body: str = "Detail body.") -> Finding:
    return Finding(
        finding_id=fid,
        nomination_id="N-1",
        flow_id="flow-1",
        cwe=cwe,
        status="verified",
        title=f"SQL injection ({fid})",
        body=body,
    )


def test_render_empty_report(tmp_path: Path) -> None:
    path = render_html_report([], out_dir=tmp_path / "report")
    assert path.name == "report.html"
    text = path.read_text(encoding="utf-8")
    assert "No findings" in text
    assert text.startswith("<!doctype html>")


def test_render_findings_have_title_badge_summary_detail(tmp_path: Path) -> None:
    body = "This endpoint concatenates request input into SQL.\nNo parameterization."
    path = render_html_report([_finding(body=body)], out_dir=tmp_path / "report")
    text = path.read_text(encoding="utf-8")
    # Title.
    assert "SQL injection (F-1)" in text
    # Criticality badge — CWE-89 is critical.
    assert '<span class="badge critical">critical</span>' in text
    # Summary line.
    assert "concatenates request input into SQL" in text
    # Full detail behind a <details> toggle.
    assert "<details>" in text
    assert "No parameterization." in text


def test_render_escapes_html_in_finding_body(tmp_path: Path) -> None:
    """A finding body carries source code — it must be HTML-escaped."""
    path = render_html_report(
        [_finding(body="<script>alert(1)</script> payload")],
        out_dir=tmp_path / "report",
    )
    text = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_render_sorts_by_severity(tmp_path: Path) -> None:
    findings = [
        _finding(fid="F-low", cwe="CWE-532"),  # low
        _finding(fid="F-crit", cwe="CWE-89"),  # critical
    ]
    text = render_html_report(findings, out_dir=tmp_path / "report").read_text(encoding="utf-8")
    assert text.index("F-crit") < text.index("F-low")


def test_render_with_conn_writes_graph_pages(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    conn.execute(
        "INSERT INTO flows (fid, tid, sid, cwe, engine, steps_json) VALUES "
        "('flow-1', 't', 's', 'CWE-89', 'joern', ?)",
        [json.dumps([["app.py", 10, 10], ["db.py", 20, 20]])],
    )
    out = tmp_path / "report"
    render_html_report([_finding()], out_dir=out, conn=conn, target_name="myapp")

    assert (out / "report.html").is_file()
    assert (out / "call-graph.html").is_file()
    assert (out / "entrypoints.html").is_file()
    # The finding has a flow -> a per-finding flow graph page exists and is linked.
    assert (out / "flow-F-1.html").is_file()
    report = (out / "report.html").read_text(encoding="utf-8")
    assert 'href="flow-F-1.html"' in report
    assert 'href="call-graph.html"' in report
    assert "myapp" in report


def test_flow_graph_page_embeds_react_flow_and_steps(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    conn.execute(
        "INSERT INTO flows (fid, tid, sid, cwe, engine, steps_json) VALUES "
        "('flow-1', 't', 's', 'CWE-89', 'joern', ?)",
        [json.dumps([["app.py", 10, 10], ["db.py", 20, 20]])],
    )
    out = tmp_path / "report"
    render_html_report([_finding()], out_dir=out, conn=conn)
    flow_html = (out / "flow-F-1.html").read_text(encoding="utf-8")
    assert "reactflow" in flow_html  # React Flow loaded
    # The embedded graph data names both flow-step files.
    data = json.loads(flow_html.split('type="application/json">')[1].split("</script>")[0])
    labels = " ".join(n["data"]["label"] for n in data["nodes"])
    assert "app.py" in labels
    assert "db.py" in labels
    assert "source:" in labels and "sink:" in labels
