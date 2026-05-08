"""Ingest detected entrypoints into the DuckDB ``entrypoints`` table."""

from __future__ import annotations

from collections.abc import Iterable

import duckdb

from ai_codescan.entrypoints.detectors import Entrypoint


def ingest_entrypoints(
    conn: duckdb.DuckDBPyConnection,
    entrypoints: Iterable[Entrypoint],
) -> int:
    rows = [(e.symbol_id, e.kind, e.signature) for e in entrypoints]
    if not rows:
        return 0
    conn.executemany("INSERT INTO entrypoints VALUES (?, ?, ?)", rows)
    return len(rows)
