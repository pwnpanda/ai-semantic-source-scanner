"""Ingest AST records (and optional SCIP lookup) into DuckDB."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import duckdb

from ai_codescan.source_paths import resolve_contained_file

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


def _file_rows(
    files: Iterable[dict[str, Any]], snapshot_root: Path, project_id: str
) -> list[tuple[Any, ...]]:
    rows = []
    for record in files:
        path = resolve_contained_file(snapshot_root, str(record["file"]))
        rows.append(
            (
                path.as_posix(),
                _file_sha256(path),
                record.get("lang", "unknown"),
                project_id,
                path.stat().st_size,
            )
        )
    return rows


def _symbol_rows(
    symbols: Iterable[dict[str, Any]],
    snapshot_root: Path,
    scip_lookup: ScipLookup,
) -> list[tuple[Any, ...]]:
    rows = []
    for record in symbols:
        symbol_id = _resolve_symbol_id(record, scip_lookup)
        if not symbol_id:
            continue
        file = resolve_contained_file(snapshot_root, str(record["file"])).as_posix()
        rows.append(
            (
                symbol_id,
                symbol_id,
                record["kind"],
                file,
                record["range"][0],
                record["range"][1],
                None,
                record.get("name"),
            )
        )
    return rows


def _xref_rows(xrefs: Iterable[dict[str, Any]], snapshot_root: Path) -> list[tuple[Any, ...]]:
    rows = []
    for record in xrefs:
        raw_file = record.get("file")
        file = resolve_contained_file(snapshot_root, str(raw_file)).as_posix() if raw_file else None
        rows.append(
            (
                record.get("callerSyntheticId"),
                None,
                record["kind"],
                file,
                record.get("line"),
            )
        )
    return rows


def _insert_rows(conn: duckdb.DuckDBPyConnection, query: str, rows: list[tuple[Any, ...]]) -> None:
    if rows:
        conn.executemany(query, rows)


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
    file_rows = _file_rows(files, snapshot_root, project_id)
    symbol_rows = _symbol_rows(symbols, snapshot_root, scip_lookup)
    xref_rows = _xref_rows(xrefs, snapshot_root)
    _insert_rows(
        conn,
        "INSERT OR REPLACE INTO files VALUES (?, ?, ?, ?, ?)",
        file_rows,
    )
    _insert_rows(
        conn,
        "INSERT OR REPLACE INTO symbols VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        symbol_rows,
    )
    _insert_rows(
        conn,
        "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?)",
        xref_rows,
    )
