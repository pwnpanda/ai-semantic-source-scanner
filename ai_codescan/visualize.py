"""Render flows + xrefs as a Graphviz DOT graph and (optionally) an SVG/PNG.

Phase 3B picks Graphviz over interactive options (React Flow, Cytoscape) because
``dot`` is universally available, scales to thousands of nodes, and renders to
both static images and interactive SVG without any server. Future work can add
a React Flow front-end on top of the same DuckDB index — see TRADEOFFS.md.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Literal

import duckdb

OutputFormat = Literal["dot", "svg", "png"]


def _short_label(text: str, *, max_chars: int = 40) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1] + "…"


def _node_id(prefix: str, raw: str) -> str:
    """Make a DOT-safe identifier from arbitrary text."""
    safe = "".join(c if c.isalnum() else "_" for c in raw)[:64]
    return f"{prefix}_{safe}"


def render_flows_dot(
    conn: duckdb.DuckDBPyConnection,
    *,
    cwe: str | None = None,
    limit: int = 200,
) -> str:
    """Render flows as a DOT graph string.

    Optional ``cwe`` filter restricts to one bug class. Each flow becomes:

        source ──▶ ... ──▶ sink   (edge label: CWE)

    Sources are blue circles, sinks are red boxes, intermediates are grey.
    """
    if cwe:
        rows = conn.execute(
            """
            SELECT f.fid, f.cwe, f.engine, f.confidence, s.evidence_loc, t.class
            FROM flows f
            JOIN taint_sources s ON s.tid = f.tid
            JOIN taint_sinks   t ON t.sid = f.sid
            WHERE f.cwe = ?
            LIMIT ?
            """,
            [cwe, limit],
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT f.fid, f.cwe, f.engine, f.confidence, s.evidence_loc, t.class
            FROM flows f
            JOIN taint_sources s ON s.tid = f.tid
            JOIN taint_sinks   t ON t.sid = f.sid
            LIMIT ?
            """,
            [limit],
        ).fetchall()

    lines: list[str] = [
        "digraph flows {",
        '  graph [rankdir=LR, fontname="Helvetica", concentrate=true];',
        '  node  [fontname="Helvetica", fontsize=10];',
        '  edge  [fontname="Helvetica", fontsize=9];',
    ]
    seen_nodes: set[str] = set()
    for fid, flow_cwe, engine, confidence, source_loc, sink_class in rows:
        src_node = _node_id("src", source_loc or fid)
        sink_node = _node_id("snk", sink_class or fid)
        if src_node not in seen_nodes:
            lines.append(
                f'  {src_node} [shape=circle, style=filled, fillcolor="#cfe2ff", '
                f'label="{_short_label(source_loc or "")}"];'
            )
            seen_nodes.add(src_node)
        if sink_node not in seen_nodes:
            lines.append(
                f'  {sink_node} [shape=box, style=filled, fillcolor="#f8d7da", '
                f'label="{_short_label(sink_class or "")}"];'
            )
            seen_nodes.add(sink_node)
        edge_label = f"{flow_cwe or '?'} ({engine}, {confidence})"
        lines.append(
            f'  {src_node} -> {sink_node} [label="{_short_label(edge_label)}"];'
        )
    lines.append("}")
    return "\n".join(lines)


def render(
    conn: duckdb.DuckDBPyConnection,
    *,
    out_path: Path,
    fmt: OutputFormat = "svg",
    cwe: str | None = None,
    limit: int = 200,
) -> Path:
    """Render flows to ``out_path`` in the requested format.

    ``fmt='dot'`` writes raw DOT. ``svg`` / ``png`` shells out to ``dot``.
    """
    dot_text = render_flows_dot(conn, cwe=cwe, limit=limit)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "dot":
        out_path.write_text(dot_text, encoding="utf-8")
        return out_path

    if shutil.which("dot") is None:
        raise RuntimeError(
            "graphviz `dot` is not on PATH. "
            "Install it (apt-get install graphviz) or pass --fmt dot."
        )

    proc = subprocess.run(  # noqa: S603 - argv-only, no shell
        ["dot", f"-T{fmt}", "-o", str(out_path)],  # noqa: S607
        input=dot_text,
        text=True,
        capture_output=True,
        check=True,
    )
    _ = proc  # silence "unused"
    return out_path
