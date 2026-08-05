"""Whole-repo call graph from the DuckDB SCIP cross-reference index.

The HTML report's default view is a call graph with finding paths marked.
The data already exists: `symbols` holds every declared symbol, `xrefs`
holds caller -> callee edges from the SCIP indexer. This module collapses
those into a node/edge JSON shape a React Flow front-end can render.

Nodes that sit on a finding's source or sink file are flagged so the
report can highlight the vulnerable region of the graph.

Defensive throughout — a repo scanned without a SCIP index simply yields
an empty graph rather than an error.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from typing import Any

import duckdb

log = logging.getLogger(__name__)

# `symbols.kind` values that are call-graph nodes. SCIP emits many kinds
# (variables, parameters, ...); only callable-ish symbols belong on a
# call graph. Kept broad — a missing kind just drops a node, recall-first
# does not apply to a visualisation but over-pruning still hides context.
_CALLABLE_KINDS = frozenset({"function", "method", "constructor", "func", "def", "procedure"})


@dataclass(frozen=True, slots=True)
class CallGraphNode:
    id: str
    label: str
    file: str
    kind: str
    on_finding_path: bool = False

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CallGraphEdge:
    source: str
    target: str
    kind: str

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


def _table_exists(conn: duckdb.DuckDBPyConnection, name: str) -> bool:
    row = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
        [name],
    ).fetchone()
    return bool(row and int(row[0]) > 0)


def finding_files(conn: duckdb.DuckDBPyConnection) -> set[str]:
    """Every file that appears along any recorded flow path.

    A flow's ``steps_json`` is a list of ``[file, start_line, end_line]``
    steps from source to sink; the file of each step is on a finding path.
    Empty when there are no flows yet.
    """
    if not _table_exists(conn, "flows"):
        return set()
    rows = conn.execute("SELECT steps_json FROM flows").fetchall()
    files: set[str] = set()
    for (steps_json,) in rows:
        try:
            steps = json.loads(steps_json or "[]")
        except json.JSONDecodeError:
            continue
        for step in steps:
            if isinstance(step, list) and step and step[0]:
                files.add(str(step[0]))
    return files


def build_call_graph(
    conn: duckdb.DuckDBPyConnection,
    *,
    marked_files: set[str] | None = None,
    max_nodes: int = 1500,
) -> dict[str, list[dict[str, Any]]]:
    """Return ``{"nodes": [...], "edges": [...]}`` for the whole repo.

    ``marked_files`` — files to flag as on a finding path (defaults to
    `finding_files(conn)`). ``max_nodes`` caps the graph so a huge repo
    does not produce an unusable render; when the cap trips, nodes on a
    finding path are kept preferentially.
    """
    if not (_table_exists(conn, "symbols") and _table_exists(conn, "xrefs")):
        return {"nodes": [], "edges": []}
    marked = marked_files if marked_files is not None else finding_files(conn)

    sym_rows = conn.execute(
        "SELECT id, COALESCE(NULLIF(display_name, ''), sym), kind, file FROM symbols"
    ).fetchall()
    nodes: dict[str, CallGraphNode] = {}
    for sid, label, kind, file in sym_rows:
        if str(kind).lower() not in _CALLABLE_KINDS:
            continue
        file_str = str(file or "")
        on_path = (
            any(file_str.endswith(m) or m.endswith(file_str) for m in marked)
            if (marked and file_str)
            else False
        )
        nodes[str(sid)] = CallGraphNode(
            id=str(sid),
            label=str(label or sid),
            file=file_str,
            kind=str(kind),
            on_finding_path=on_path,
        )

    edge_rows = conn.execute(
        "SELECT caller_id, callee_id, kind FROM xrefs "
        "WHERE caller_id IS NOT NULL AND callee_id IS NOT NULL"
    ).fetchall()
    edges: list[CallGraphEdge] = []
    for caller, callee, kind in edge_rows:
        if str(caller) in nodes and str(callee) in nodes:
            edges.append(CallGraphEdge(str(caller), str(callee), str(kind or "call")))

    if len(nodes) > max_nodes:
        # Keep finding-path nodes + their immediate neighbours; drop the rest.
        keep = {nid for nid, n in nodes.items() if n.on_finding_path}
        for edge in edges:
            if edge.source in keep or edge.target in keep:
                keep.add(edge.source)
                keep.add(edge.target)
        # Top up to the cap with arbitrary remaining nodes for context.
        for nid in nodes:
            if len(keep) >= max_nodes:
                break
            keep.add(nid)
        nodes = {nid: n for nid, n in nodes.items() if nid in keep}
        edges = [e for e in edges if e.source in nodes and e.target in nodes]

    return {
        "nodes": [n.to_jsonable() for n in nodes.values()],
        "edges": [e.to_jsonable() for e in edges],
    }
