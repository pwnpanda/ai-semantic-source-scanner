"""Tests for ai_codescan.call_graph — whole-repo call graph from xrefs/symbols."""

from __future__ import annotations

from pathlib import Path

import duckdb

from ai_codescan.call_graph import build_call_graph, finding_files
from ai_codescan.index.duckdb_schema import apply_schema


def _conn(tmp_path: Path) -> duckdb.DuckDBPyConnection:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    return conn


def _add_symbol(conn, sid: str, name: str, kind: str, file: str) -> None:
    conn.execute(
        "INSERT INTO symbols (id, sym, kind, file, range_start, range_end, display_name) "
        "VALUES (?, ?, ?, ?, 1, 2, ?)",
        [sid, name, kind, file, name],
    )


def test_build_call_graph_empty_when_no_index(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "bare.duckdb"))
    assert build_call_graph(conn) == {"nodes": [], "edges": []}


def test_build_call_graph_keeps_only_callable_kinds(tmp_path: Path) -> None:
    conn = _conn(tmp_path)
    _add_symbol(conn, "s1", "handler", "function", "app.py")
    _add_symbol(conn, "s2", "config", "variable", "app.py")  # not callable
    graph = build_call_graph(conn)
    labels = {n["label"] for n in graph["nodes"]}
    assert labels == {"handler"}


def test_build_call_graph_edges_only_between_known_nodes(tmp_path: Path) -> None:
    conn = _conn(tmp_path)
    _add_symbol(conn, "s1", "route", "function", "app.py")
    _add_symbol(conn, "s2", "query", "function", "db.py")
    conn.execute("INSERT INTO xrefs (caller_id, callee_id, kind) VALUES ('s1', 's2', 'call')")
    # An edge to an unknown callee is dropped.
    conn.execute("INSERT INTO xrefs (caller_id, callee_id, kind) VALUES ('s1', 'ghost', 'call')")
    graph = build_call_graph(conn)
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["source"] == "s1"
    assert graph["edges"][0]["target"] == "s2"


def test_build_call_graph_marks_finding_path_nodes(tmp_path: Path) -> None:
    conn = _conn(tmp_path)
    _add_symbol(conn, "s1", "vuln_route", "function", "app/handlers.py")
    _add_symbol(conn, "s2", "safe_util", "function", "app/util.py")
    graph = build_call_graph(conn, marked_files={"app/handlers.py"})
    by_label = {n["label"]: n for n in graph["nodes"]}
    assert by_label["vuln_route"]["on_finding_path"] is True
    assert by_label["safe_util"]["on_finding_path"] is False


def test_build_call_graph_caps_node_count(tmp_path: Path) -> None:
    conn = _conn(tmp_path)
    for i in range(50):
        _add_symbol(conn, f"s{i}", f"fn{i}", "function", f"f{i}.py")
    graph = build_call_graph(conn, max_nodes=10)
    assert len(graph["nodes"]) <= 10


def test_finding_files_empty_without_flows(tmp_path: Path) -> None:
    conn = _conn(tmp_path)
    assert finding_files(conn) == set()
