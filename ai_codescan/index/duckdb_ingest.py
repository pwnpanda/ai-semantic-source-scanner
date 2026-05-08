"""Ingest AST records (and optional SCIP lookup) into DuckDB."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import duckdb

ScipLookup = dict[tuple[str, int, int], str]
"""Map of (file, range_start, range_end) → SCIP symbol id."""


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    if not path.is_file():
        return ""
    with path.open("rb") as f:
        while chunk := f.read(65_536):
            h.update(chunk)
    return h.hexdigest()


def _resolve_symbol_id(record: dict[str, Any], scip_lookup: ScipLookup) -> str | None:
    file = record["file"]
    rng = record.get("range")
    if rng:
        scip = scip_lookup.get((file, rng[0], rng[1]))
        if scip:
            return scip
    return record.get("syntheticId")


def ingest(  # noqa: PLR0913 - cohesive bulk-ingest entrypoint, kw-only args
    conn: duckdb.DuckDBPyConnection,
    *,
    files: Iterable[dict[str, Any]],
    symbols: Iterable[dict[str, Any]],
    xrefs: Iterable[dict[str, Any]],
    scip_lookup: ScipLookup,
    project_id: str,
    snapshot_root: Path,
) -> None:
    """Bulk-ingest AST + SCIP records into DuckDB tables."""
    del snapshot_root  # reserved for future cross-referencing
    file_rows = []
    for f in files:
        path = Path(f["file"])
        rel = path.as_posix()
        sha = _file_sha256(path) if path.is_absolute() and path.exists() else ""
        size = path.stat().st_size if path.is_file() else 0
        file_rows.append((rel, sha, f.get("lang", "unknown"), project_id, size))
    if file_rows:
        conn.executemany(
            "INSERT OR REPLACE INTO files VALUES (?, ?, ?, ?, ?)",
            file_rows,
        )

    sym_rows = []
    for s in symbols:
        sid = _resolve_symbol_id(s, scip_lookup)
        if not sid:
            continue
        sym_rows.append(
            (
                sid,
                sid,
                s["kind"],
                s["file"],
                s["range"][0],
                s["range"][1],
                None,
                s.get("name"),
            )
        )
    if sym_rows:
        conn.executemany(
            "INSERT OR REPLACE INTO symbols VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            sym_rows,
        )

    xref_rows = []
    for x in xrefs:
        xref_rows.append(
            (
                x.get("callerSyntheticId"),
                None,
                x["kind"],
                x.get("file"),
                x.get("line"),
            )
        )
    if xref_rows:
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?)",
            xref_rows,
        )
