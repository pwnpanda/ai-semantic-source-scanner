"""Self-contained HTML report.

The pipeline's consumable end product. Structure:

- ``report.html`` — the findings list. Each finding is a card with its
  title + criticality badge, a 2-4 line summary, the full detail behind a
  native ``<details>`` toggle (collapsed by default), and a link to its
  flow graph. Pure HTML/CSS — no JavaScript, so it always renders.
- ``call-graph.html`` — the whole-repo call graph with finding paths
  marked. React Flow via esm.sh (no build step).
- ``flow-<finding>.html`` — one per finding, the source -> sink path.
- ``entrypoints.html`` — entrypoint -> sink reachability map.

Graph pages are linked, not inlined, so the initial report page stays
light. The graph pages need a browser with network access (esm.sh CDN).
"""

from __future__ import annotations

import html
import json
import logging
from pathlib import Path
from typing import Any

import duckdb

from ai_codescan.call_graph import build_call_graph
from ai_codescan.findings.model import Finding
from ai_codescan.report import derive_meta

log = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_REPORT_CSS = """\
:root { color-scheme: light dark; }
body { font: 15px/1.55 -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
       background: #f6f7f9; color: #1a1a1a; }
header { background: #1f2937; color: #fff; padding: 20px 32px; }
header h1 { margin: 0 0 4px; font-size: 20px; }
header .meta { color: #9ca3af; font-size: 13px; }
main { max-width: 960px; margin: 0 auto; padding: 24px 32px 64px; }
.nav { margin: 12px 0 24px; }
.nav a { display: inline-block; margin-right: 12px; padding: 6px 12px;
         background: #e5e7eb; border-radius: 6px; text-decoration: none;
         color: #1f2937; font-size: 13px; }
.finding { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;
           margin-bottom: 16px; overflow: hidden; }
.finding-head { display: flex; align-items: center; gap: 12px; padding: 14px 18px;
                border-bottom: 1px solid #f0f0f0; }
.finding-head h2 { margin: 0; font-size: 16px; flex: 1; }
.badge { font-size: 11px; font-weight: 700; text-transform: uppercase;
         padding: 3px 9px; border-radius: 12px; color: #fff; white-space: nowrap; }
.badge.critical { background: #b91c1c; }
.badge.high     { background: #ea580c; }
.badge.medium   { background: #ca8a04; }
.badge.low      { background: #2563eb; }
.badge.informational { background: #6b7280; }
.cwe { font-size: 12px; color: #6b7280; }
.summary { padding: 12px 18px; margin: 0; color: #374151; }
details { padding: 0 18px 14px; }
details summary { cursor: pointer; font-size: 13px; color: #2563eb; padding: 6px 0; }
details pre { background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 6px;
              overflow-x: auto; font-size: 12.5px; line-height: 1.45; }
.finding-foot { padding: 0 18px 14px; }
.finding-foot a { font-size: 13px; }
.empty { color: #6b7280; padding: 40px; text-align: center; }
"""


def _summary_lines(body: str, *, max_lines: int = 4) -> str:
    """First few non-empty, non-heading lines of a finding body."""
    out: list[str] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("```"):
            continue
        out.append(line)
        if len(out) >= max_lines:
            break
    return " ".join(out) if out else "(no summary available)"


def _finding_card(finding: Finding, severity: str, *, has_flow: bool) -> str:
    sev = severity if severity in _SEVERITY_ORDER else "informational"
    cwe = html.escape(finding.cwe or "—")
    title = html.escape(finding.title or finding.finding_id)
    summary = html.escape(_summary_lines(finding.body))
    detail = html.escape(finding.body or "(no detail)")
    flow_link = (
        f'<div class="finding-foot"><a href="flow-{html.escape(finding.finding_id)}.html">'
        "View data-flow graph &rarr;</a></div>"
        if has_flow
        else ""
    )
    return f"""\
<section class="finding">
  <div class="finding-head">
    <span class="badge {sev}">{sev}</span>
    <h2>{title}</h2>
    <span class="cwe">{cwe}</span>
  </div>
  <p class="summary">{summary}</p>
  <details>
    <summary>Full detail &mdash; source, evidence, analysis</summary>
    <pre>{detail}</pre>
  </details>
  {flow_link}
</section>"""


# --- graph pages (React Flow via esm.sh) -------------------------------------

_GRAPH_PAGE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<link rel="stylesheet" href="https://esm.sh/reactflow@11.11.4/dist/style.css">
<style>
  html, body, #root {{ height: 100%; margin: 0; }}
  body {{ font: 14px sans-serif; }}
  .legend {{ position: fixed; top: 10px; right: 10px; z-index: 10; background: #fff;
             border: 1px solid #ddd; border-radius: 6px; padding: 8px 12px; font-size: 12px; }}
  .swatch {{ display: inline-block; width: 11px; height: 11px; border-radius: 2px;
             vertical-align: middle; margin-right: 5px; }}
</style>
<script type="importmap">
{{"imports": {{
  "react": "https://esm.sh/react@18.3.1",
  "react-dom": "https://esm.sh/react-dom@18.3.1",
  "react-dom/client": "https://esm.sh/react-dom@18.3.1/client",
  "reactflow": "https://esm.sh/reactflow@11.11.4?deps=react@18.3.1,react-dom@18.3.1"
}}}}
</script>
</head>
<body>
<div class="legend"><span class="swatch" style="background:#b91c1c"></span>on a finding path
  &nbsp; <span class="swatch" style="background:#e5e7eb"></span>other</div>
<div id="root"></div>
<script id="graph-data" type="application/json">{data}</script>
<script type="module">
import React from "react";
import {{ createRoot }} from "react-dom/client";
import ReactFlow, {{ Background, Controls, MiniMap }} from "reactflow";

const data = JSON.parse(document.getElementById("graph-data").textContent);
function App() {{
  return React.createElement(
    ReactFlow,
    {{ nodes: data.nodes, edges: data.edges, fitView: true, minZoom: 0.05 }},
    React.createElement(Background, null),
    React.createElement(Controls, null),
    React.createElement(MiniMap, null),
  );
}}
createRoot(document.getElementById("root")).render(React.createElement(App));
</script>
</body>
</html>"""


def _grid_positions(count: int, *, gap_x: int = 240, gap_y: int = 90) -> list[dict[str, int]]:
    """Deterministic grid layout — React Flow needs explicit node positions
    and we ship no layout engine. A grid is legible enough for a report."""
    if count <= 0:
        return []
    width = max(1, int(count**0.5))
    return [{"x": (i % width) * gap_x, "y": (i // width) * gap_y} for i in range(count)]


def _call_graph_page(conn: duckdb.DuckDBPyConnection) -> str:
    graph = build_call_graph(conn)
    positions = _grid_positions(len(graph["nodes"]))
    rf_nodes = [
        {
            "id": n["id"],
            "position": positions[i],
            "data": {"label": n["label"]},
            "style": _node_style(n["on_finding_path"]),
        }
        for i, n in enumerate(graph["nodes"])
    ]
    rf_edges = [
        {"id": f"e{i}", "source": e["source"], "target": e["target"], "animated": False}
        for i, e in enumerate(graph["edges"])
    ]
    payload = json.dumps({"nodes": rf_nodes, "edges": rf_edges})
    return _GRAPH_PAGE.format(title="Call graph", data=payload)


def _node_style(on_path: bool) -> dict[str, str]:
    if on_path:
        return {"background": "#b91c1c", "color": "#fff", "border": "1px solid #7f1d1d"}
    return {"background": "#e5e7eb", "color": "#1f2937", "border": "1px solid #d1d5db"}


def _flow_steps(conn: duckdb.DuckDBPyConnection, flow_id: str) -> list[list[Any]]:
    if not flow_id:
        return []
    row = conn.execute("SELECT steps_json FROM flows WHERE fid = ?", [flow_id]).fetchone()
    if row is None or not row[0]:
        return []
    try:
        steps = json.loads(row[0])
    except json.JSONDecodeError:
        return []
    return [s for s in steps if isinstance(s, list) and s]


def _flow_graph_page(finding: Finding, steps: list[list[Any]]) -> str:
    """A finding's flow graph — a vertical source -> sink chain."""
    rf_nodes = []
    rf_edges = []
    for i, step in enumerate(steps):
        file = str(step[0]) if step else "?"
        line = step[1] if len(step) > 1 else ""
        role = "source" if i == 0 else "sink" if i == len(steps) - 1 else "step"
        rf_nodes.append(
            {
                "id": f"s{i}",
                "position": {"x": 0, "y": i * 110},
                "data": {"label": f"{role}: {file}:{line}"},
                "style": _node_style(role in {"source", "sink"}),
            }
        )
        if i > 0:
            rf_edges.append(
                {"id": f"e{i}", "source": f"s{i - 1}", "target": f"s{i}", "animated": True}
            )
    payload = json.dumps({"nodes": rf_nodes, "edges": rf_edges})
    return _GRAPH_PAGE.format(title=f"Flow: {finding.title}", data=payload)


def _entrypoints_page(conn: duckdb.DuckDBPyConnection) -> str:
    """Entrypoint -> sink reachability map."""
    rf_nodes: list[dict[str, Any]] = []
    rf_edges: list[dict[str, Any]] = []
    has_ep = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'entrypoints'"
    ).fetchone()
    if has_ep and int(has_ep[0]) > 0:
        rows = conn.execute("SELECT DISTINCT file, COALESCE(kind, '') FROM entrypoints").fetchall()
        for i, (file, kind) in enumerate(rows):
            rf_nodes.append(
                {
                    "id": f"ep{i}",
                    "position": {"x": 0, "y": i * 80},
                    "data": {"label": f"{kind or 'entrypoint'}: {file}"},
                    "style": _node_style(True),
                }
            )
    payload = json.dumps({"nodes": rf_nodes, "edges": rf_edges})
    return _GRAPH_PAGE.format(title="Entrypoints", data=payload)


def render_html_report(
    findings: list[Finding],
    *,
    out_dir: Path,
    conn: duckdb.DuckDBPyConnection | None = None,
    target_name: str = "",
) -> Path:
    """Write the full HTML report tree. Returns the path of ``report.html``.

    ``findings`` are rendered as cards sorted by severity. ``conn`` (the
    DuckDB index) drives the graph pages — when None, only the findings
    list is written.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    ranked: list[tuple[int, Finding, str]] = []
    for finding in findings:
        severity = derive_meta(finding).severity
        ranked.append((_SEVERITY_ORDER.get(severity, 4), finding, severity))
    ranked.sort(key=lambda t: (t[0], t[1].finding_id))

    cards: list[str] = []
    for _, finding, severity in ranked:
        steps = _flow_steps(conn, finding.flow_id) if conn is not None else []
        has_flow = bool(steps)
        if has_flow and conn is not None:
            (out_dir / f"flow-{finding.finding_id}.html").write_text(
                _flow_graph_page(finding, steps), encoding="utf-8"
            )
        cards.append(_finding_card(finding, severity, has_flow=has_flow))

    nav_links = ['<a href="report.html">Findings</a>']
    if conn is not None:
        (out_dir / "call-graph.html").write_text(_call_graph_page(conn), encoding="utf-8")
        (out_dir / "entrypoints.html").write_text(_entrypoints_page(conn), encoding="utf-8")
        nav_links.append('<a href="call-graph.html">Call graph</a>')
        nav_links.append('<a href="entrypoints.html">Entrypoints</a>')

    body = "\n".join(cards) if cards else '<p class="empty">No findings.</p>'
    title = html.escape(target_name or "ai-codescan")
    report = f"""\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security report — {title}</title>
<style>{_REPORT_CSS}</style>
</head>
<body>
<header>
  <h1>Security report — {title}</h1>
  <div class="meta">{len(findings)} finding(s) &middot; ai-codescan</div>
</header>
<main>
  <div class="nav">{" ".join(nav_links)}</div>
  {body}
</main>
</body>
</html>"""
    report_path = out_dir / "report.html"
    report_path.write_text(report, encoding="utf-8")
    return report_path
