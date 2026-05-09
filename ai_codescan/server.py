"""Tiny HTTP server backing the React Flow viewer.

Serves a static React Flow page plus a small JSON API over the cached
DuckDB so a human reviewer can pan/zoom flows and pin notes per symbol.
The interactive viewer is purely additive — Graphviz export via
``ai-codescan visualize`` remains the default and works offline.

Endpoints:

- ``GET  /``                      static viewer (React Flow via CDN)
- ``GET  /api/flows[?cwe=&limit=]`` nodes + edges + flows JSON
- ``GET  /api/notes/<symbol_id>``  list notes for a symbol
- ``POST /api/notes``              ``{symbol_id, content[, author, layer, pinned]}``
- ``DELETE /api/notes/<row_id>``   remove a note row
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import duckdb

STATIC_DIR = Path(__file__).resolve().parent / "web" / "static"
log = logging.getLogger(__name__)

# Cap a single API response so the viewer stays responsive on large repos.
_MAX_FLOWS = 2000
_MAX_NODES = 5000


def _open_db(db_path: Path, *, read_only: bool) -> duckdb.DuckDBPyConnection:
    return duckdb.connect(str(db_path), read_only=read_only)


def _flows_payload(
    conn: duckdb.DuckDBPyConnection,
    *,
    cwe: str | None = None,
    limit: int = _MAX_FLOWS,
) -> dict[str, Any]:
    """Return nodes/edges/flows for the React Flow viewer."""
    limit = max(1, min(limit, _MAX_FLOWS))

    where = ""
    params: list[Any] = []
    if cwe:
        where = "WHERE f.cwe = ?"
        params = [cwe]

    # `where` is built from a fixed set of literals; only `params` carries user input.
    # `limit` is clamped to an int above. ruff S608 disabled with that justification.
    flow_rows = conn.execute(
        f"""
        SELECT f.fid, f.tid, f.sid, f.cwe, f.engine, f.confidence,
               s.evidence_loc AS source_loc,
               t.class AS sink_class, t.lib AS sink_lib, t.parameterization
        FROM flows f
        JOIN taint_sources s ON s.tid = f.tid
        JOIN taint_sinks   t ON t.sid = f.sid
        {where}
        LIMIT {limit}
        """,  # noqa: S608 - `where` and `limit` are built from sanitized values
        params,
    ).fetchall()

    flows: list[dict[str, Any]] = []
    seen: set[str] = set()
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def _add_node(node_id: str, kind: str, label: str, extra: dict[str, Any]) -> None:
        if node_id in seen or len(nodes) >= _MAX_NODES:
            return
        seen.add(node_id)
        nodes.append({"id": node_id, "kind": kind, "label": label, **extra})

    for fid, tid, sid, cwe_v, engine, conf, src_loc, sink_class, sink_lib, param in flow_rows:
        flows.append(
            {
                "fid": fid,
                "tid": tid,
                "sid": sid,
                "cwe": cwe_v,
                "engine": engine,
                "confidence": conf,
                "source_loc": src_loc,
                "sink_class": sink_class,
                "sink_lib": sink_lib,
                "parameterization": param,
            }
        )
        _add_node(
            f"src:{tid}",
            "source",
            f"{src_loc or tid}",
            {"loc": src_loc, "tid": tid},
        )
        _add_node(
            f"sink:{sid}",
            "sink",
            f"{sink_class or 'sink'} ({sink_lib or '?'})",
            {"sid": sid, "class": sink_class, "lib": sink_lib, "parameterization": param},
        )
        edges.append(
            {
                "id": fid,
                "source": f"src:{tid}",
                "target": f"sink:{sid}",
                "cwe": cwe_v,
                "engine": engine,
                "confidence": conf,
            }
        )

    return {"nodes": nodes, "edges": edges, "flows": flows}


def _notes_for(conn: duckdb.DuckDBPyConnection, symbol_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT rowid, symbol_id, layer, author, content, pinned, ts
        FROM notes WHERE symbol_id = ? ORDER BY ts DESC
        """,
        [symbol_id],
    ).fetchall()
    return [
        {
            "rowid": int(rid),
            "symbol_id": sid,
            "layer": layer,
            "author": author,
            "content": content,
            "pinned": bool(pinned),
            "ts": str(ts),
        }
        for rid, sid, layer, author, content, pinned, ts in rows
    ]


def _insert_note(conn: duckdb.DuckDBPyConnection, payload: dict[str, Any]) -> int:
    sid = str(payload["symbol_id"])
    layer = str(payload.get("layer", "human"))
    author = str(payload.get("author", "human"))
    content = str(payload["content"])
    pinned = bool(payload.get("pinned", False))
    conn.execute(
        "INSERT INTO notes (symbol_id, layer, author, content, pinned)"
        " VALUES (?, ?, ?, ?, ?)",
        [sid, layer, author, content, pinned],
    )
    # Return inserted rowid via the latest matching row.
    row = conn.execute(
        "SELECT rowid FROM notes WHERE symbol_id = ? ORDER BY ts DESC LIMIT 1",
        [sid],
    ).fetchone()
    return int(row[0]) if row else -1


def _delete_note(conn: duckdb.DuckDBPyConnection, rowid: int) -> int:
    conn.execute("DELETE FROM notes WHERE rowid = ?", [rowid])
    return rowid


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    db_path: Path
    server_version = "ai-codescan/1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - matches stdlib signature
        log.info("%s - %s", self.address_string(), format % args)

    def _send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_static(self, path: Path) -> None:
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "file not found")
            return
        ext = path.suffix.lower()
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript",
            ".css": "text/css",
            ".svg": "image/svg+xml",
            ".json": "application/json",
        }.get(ext, "application/octet-stream")
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- routing -----

    def do_GET(self) -> None:  # noqa: N802 - http handler convention
        path, _, query = self.path.partition("?")
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)

        if path in {"/", "/index.html"}:
            self._send_static(STATIC_DIR / "index.html")
            return
        if path.startswith("/static/"):
            rel = path[len("/static/") :].lstrip("/")
            self._send_static(STATIC_DIR / rel)
            return
        if path == "/api/flows":
            cwe = params.get("cwe") or None
            try:
                limit = int(params.get("limit", _MAX_FLOWS))
            except ValueError:
                limit = _MAX_FLOWS
            conn = _open_db(self.db_path, read_only=True)
            try:
                self._send_json(HTTPStatus.OK, _flows_payload(conn, cwe=cwe, limit=limit))
            finally:
                conn.close()
            return
        if path.startswith("/api/notes/"):
            symbol_id = path[len("/api/notes/") :]
            conn = _open_db(self.db_path, read_only=True)
            try:
                self._send_json(HTTPStatus.OK, {"notes": _notes_for(conn, symbol_id)})
            finally:
                conn.close()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "unknown route")

    def do_POST(self) -> None:  # noqa: N802 - http handler convention
        if self.path != "/api/notes":
            self.send_error(HTTPStatus.NOT_FOUND, "unknown route")
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, f"invalid JSON: {exc}")
            return
        if "symbol_id" not in payload or "content" not in payload:
            self.send_error(HTTPStatus.BAD_REQUEST, "symbol_id and content required")
            return
        conn = _open_db(self.db_path, read_only=False)
        try:
            rowid = _insert_note(conn, payload)
        finally:
            conn.close()
        self._send_json(HTTPStatus.CREATED, {"rowid": rowid})

    def do_DELETE(self) -> None:  # noqa: N802 - http handler convention
        if not self.path.startswith("/api/notes/"):
            self.send_error(HTTPStatus.NOT_FOUND, "unknown route")
            return
        try:
            rowid = int(self.path[len("/api/notes/") :])
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST, "rowid must be int")
            return
        conn = _open_db(self.db_path, read_only=False)
        try:
            _delete_note(conn, rowid)
        finally:
            conn.close()
        self._send_json(HTTPStatus.OK, {"rowid": rowid})


def make_handler(db_path: Path) -> Callable[..., _Handler]:
    """Return a ``_Handler`` subclass bound to ``db_path``."""

    class Bound(_Handler):
        pass

    Bound.db_path = db_path
    return Bound


def serve(db_path: Path, *, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Start the viewer server. Caller is responsible for ``shutdown()``."""
    return ThreadingHTTPServer((host, port), make_handler(db_path))
