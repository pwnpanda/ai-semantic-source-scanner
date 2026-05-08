"""Emit per-file sidecar JSONL records derived from the DuckDB index."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import duckdb


def _records_for_file(conn: duckdb.DuckDBPyConnection, file: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    for sym_id, kind, range_start, range_end, display_name in conn.execute(
        "SELECT id, kind, range_start, range_end, display_name FROM symbols WHERE file = ?",
        [file],
    ).fetchall():
        out.append(
            {
                "id": sym_id,
                "kind": "symbol",
                "sym_kind": kind,
                "range": [range_start, range_end],
                "name": display_name,
            }
        )

    for tid, klass, key, evidence_loc in conn.execute(
        "SELECT tid, class, key, evidence_loc FROM taint_sources WHERE evidence_loc LIKE ?",
        [f"{file}:%"],
    ).fetchall():
        out.append(
            {
                "id": tid,
                "kind": "source",
                "class": klass,
                "key": key,
                "loc": evidence_loc,
            }
        )

    for sid, klass, lib, parameterization in conn.execute(
        """
        SELECT s.sid, s.class, s.lib, s.parameterization
        FROM taint_sinks s
        JOIN symbols sym ON sym.id = s.symbol_id
        WHERE sym.file = ?
        """,
        [file],
    ).fetchall():
        out.append(
            {
                "id": sid,
                "kind": "sink",
                "class": klass,
                "lib": lib,
                "parameterization": parameterization,
            }
        )

    for fid, tid, sid, cwe, engine in conn.execute(
        """
        SELECT f.fid, f.tid, f.sid, f.cwe, f.engine
        FROM flows f
        JOIN taint_sources s ON s.tid = f.tid
        WHERE s.evidence_loc LIKE ?
        """,
        [f"{file}:%"],
    ).fetchall():
        out.append(
            {"id": fid, "kind": "flow", "tid": tid, "sid": sid, "cwe": cwe, "engine": engine}
        )

    for sym_id, kind, sig in conn.execute(
        """
        SELECT e.symbol_id, e.kind, e.signature
        FROM entrypoints e
        LEFT JOIN symbols sym ON sym.id = e.symbol_id
        WHERE sym.file = ? OR e.symbol_id IS NULL
        """,
        [file],
    ).fetchall():
        out.append({"kind": "entrypoint", "ep_kind": kind, "signature": sig, "symbol_id": sym_id})

    return out


def emit_sidecars(
    conn: duckdb.DuckDBPyConnection,
    *,
    snapshot_root: Path,
) -> int:
    """Write one ``<file>.enrich.jsonl`` per file in the index. Returns count emitted."""
    files = [row[0] for row in conn.execute("SELECT path FROM files").fetchall()]
    written = 0
    for file in files:
        records = _records_for_file(conn, file)
        if not records:
            continue
        target = Path(file + ".enrich.jsonl")
        if not target.is_absolute():
            target = snapshot_root / file
            target = target.with_suffix(target.suffix + ".enrich.jsonl")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, separators=(",", ":")))
                f.write("\n")
        tmp.replace(target)
        written += 1
    return written
