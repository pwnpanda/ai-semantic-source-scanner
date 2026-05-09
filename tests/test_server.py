"""Tests for ai_codescan.server (React Flow viewer backend)."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import duckdb
import pytest

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.server import _flows_payload, serve


def _seed(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute("INSERT INTO files VALUES ('/abs/x.ts', 'sha', 'ts', 'p', 100)")
    conn.execute(
        "INSERT INTO symbols VALUES ('S1', 'sym', 'function', '/abs/x.ts', 1, 5, NULL, 'h')"
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', 'S1', 'http.body', 'name', '/abs/x.ts:2')"
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', 'S1', 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F1', 'T1', 'K1', 'CWE-89', 'codeql', '[]', '/sarif', 'definite')"
    )


def test_flows_payload_returns_nodes_edges_and_flows(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn)
    payload = _flows_payload(conn)
    assert {n["id"] for n in payload["nodes"]} == {"src:T1", "sink:K1"}
    assert payload["edges"][0]["source"] == "src:T1"
    assert payload["edges"][0]["target"] == "sink:K1"
    assert payload["flows"][0]["fid"] == "F1"


def test_flows_payload_filters_by_cwe(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn)
    payload = _flows_payload(conn, cwe="CWE-79")
    assert payload["flows"] == []
    assert payload["nodes"] == []


@pytest.fixture
def served_db(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    db_path = tmp_path / "served.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    _seed(conn)
    conn.close()
    server = serve(db_path, host="127.0.0.1", port=0)
    addr = server.server_address
    host, port = str(addr[0]), int(addr[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://{host}:{port}"
    # tiny wait for the server to bind in the thread
    time.sleep(0.05)
    try:
        yield base, db_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _http_get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=2) as r:  # noqa: S310 - test localhost
        return json.loads(r.read())


def _http_post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=2) as r:  # noqa: S310 - test localhost
        return json.loads(r.read())


def _http_delete(url: str) -> dict:
    req = urllib.request.Request(url, method="DELETE")
    with urllib.request.urlopen(req, timeout=2) as r:  # noqa: S310 - test localhost
        return json.loads(r.read())


def test_api_flows_endpoint(served_db: tuple[str, Path]) -> None:
    base, _ = served_db
    body = _http_get(base + "/api/flows")
    assert body["flows"][0]["fid"] == "F1"


def test_api_notes_round_trip(served_db: tuple[str, Path]) -> None:
    base, db_path = served_db
    created = _http_post(base + "/api/notes", {"symbol_id": "S1", "content": "first note"})
    assert created["rowid"] >= 0

    listed = _http_get(base + "/api/notes/S1")
    assert any(n["content"] == "first note" for n in listed["notes"])

    rowid = listed["notes"][0]["rowid"]
    _http_delete(base + f"/api/notes/{rowid}")

    after = _http_get(base + "/api/notes/S1")
    assert all(n["rowid"] != rowid for n in after["notes"])

    # Sanity check: write also lands in the underlying DB even after server close.
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        n = conn.execute("SELECT COUNT(*) FROM notes WHERE symbol_id = 'S1'").fetchone()
    finally:
        conn.close()
    assert n is not None


def test_static_index_html_served(served_db: tuple[str, Path]) -> None:
    base, _ = served_db
    with urllib.request.urlopen(base + "/", timeout=2) as r:  # noqa: S310
        body = r.read().decode("utf-8")
    assert "<!doctype html>" in body
    assert "/static/main.js" in body


def test_unknown_route_404(served_db: tuple[str, Path]) -> None:
    base, _ = served_db
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(base + "/api/nonsense", timeout=2)  # noqa: S310
    assert exc.value.code == 404
