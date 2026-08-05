"""Stored XSS synthesis on top of the storage-taint pipeline.

The existing `storage_taint` machinery marks a `storage_id` "dirty" when a
request-controlled value was written to it, and the `synthesize_round2_flows`
function emits ``write_origin -> write_site -> read_site`` flows that
inherit the contributing CWE (typically CWE-89 — stored SQL injection).

What's missing for **stored XSS** is the third hop: the read result flows
into an HTML render sink. Joern can't see this on its own because its
sourcePattern only matches HTTP shapes, not storage reads.

This module closes the gap with a recall-first proximity heuristic:

  For every tainted ``storage_id`` that has at least one ``storage_reads``
  row, find every Joern flow whose sink class is ``html.write`` and whose
  sink file is the SAME file as the read site. Emit a synthetic 4-step
  ``CWE-79`` flow ``[write_origin, write_site, read_site, xss_sink]``.

The same-file proximity gate is deliberately coarse — recall-first prefers
a candidate the scorer can demote over a silent miss. A reviewer (or the
adversarial validator) discards the false positives. A tighter same-function
gate is a follow-up once we wire the call-graph into the proximity check.

Idempotent: synthetic flows use a stable ``f-sxss-<sha1>`` fid; re-running
does not duplicate.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

import duckdb

log = logging.getLogger(__name__)

SYNTHETIC_ENGINE = "stored-xss-r3"


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]  # noqa: S324
    return f"{prefix}{digest}"


def _table_exists(conn: duckdb.DuckDBPyConnection, name: str) -> bool:
    row = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
        [name],
    ).fetchone()
    return bool(row and int(row[0]) > 0)


def _read_files(conn: duckdb.DuckDBPyConnection, storage_id: str) -> list[tuple[str, str]]:
    """Return ``(symbol_id, file)`` for every read of ``storage_id``.

    The file comes from joining ``storage_reads.symbol_id`` to ``symbols.file``.
    When SCIP wasn't built (no symbols rows), reads contribute no file and
    the stored-XSS pass simply produces nothing for that location.
    """
    rows = conn.execute(
        """
        SELECT sr.symbol_id, COALESCE(s.file, '')
        FROM storage_reads sr
        LEFT JOIN symbols s ON s.id = sr.symbol_id
        WHERE sr.storage_id = ?
        """,
        [storage_id],
    ).fetchall()
    return [(str(sym or ""), str(file or "")) for sym, file in rows if file]


def _xss_flows_in_file(
    conn: duckdb.DuckDBPyConnection,
    file: str,
) -> list[tuple[str, str, str | None]]:
    """Existing CWE-79 ``html.write`` flows whose sink lands in ``file``.

    Returns ``(fid, steps_json, source_tid)`` rows. ``steps_json`` is parsed
    later for the sink endpoint; ``source_tid`` is preserved so the stored
    flow can credit the *original* request source as its first step when
    available.

    We match the sink file via ``steps_json`` because the schema does not
    materialise sink_file as a column. A flow's ``steps_json`` is a list of
    ``[file, start_line, end_line]`` steps — the last element is the sink.
    """
    # Exclude our own synthetic engine — a stored-xss-r3 flow is CWE-79 too,
    # so it would otherwise become an "XSS sink" on the next run, producing
    # an infinite ladder of synthetic rows.
    rows = conn.execute(
        "SELECT fid, steps_json, tid FROM flows "
        "WHERE cwe = 'CWE-79' AND steps_json IS NOT NULL AND COALESCE(engine, '') != ?",
        [SYNTHETIC_ENGINE],
    ).fetchall()
    matching: list[tuple[str, str, str | None]] = []
    for fid, steps_json, tid in rows:
        try:
            steps = json.loads(steps_json or "[]")
        except json.JSONDecodeError:
            continue
        if not steps or not isinstance(steps[-1], list):
            continue
        sink_file = str(steps[-1][0]) if steps[-1] else ""
        if not sink_file:
            continue
        matches = sink_file == file or sink_file.endswith(file) or file.endswith(sink_file)
        if matches:
            matching.append((str(fid), str(steps_json or ""), str(tid) if tid else None))
    return matching


def _origin_step(conn: duckdb.DuckDBPyConnection, contributing_tids: list[str]) -> list[Any]:
    """Return a ``[file, line, line]`` step naming the original request source."""
    if not contributing_tids:
        return ["<unknown source>", 0, 0]
    row = conn.execute(
        "SELECT evidence_loc FROM taint_sources WHERE tid = ? AND evidence_loc IS NOT NULL",
        [contributing_tids[0]],
    ).fetchone()
    if not (row and row[0]):
        return ["<unknown source>", 0, 0]
    loc = str(row[0])
    file, _, line = loc.rpartition(":")
    try:
        line_no = int(line) if line else 0
    except ValueError:
        line_no = 0
    return [file or loc, line_no, line_no]


def synthesize_stored_xss_flows(conn: duckdb.DuckDBPyConnection) -> int:  # noqa: PLR0912 - proximity composition is intentionally flat
    """Emit synthetic stored-XSS flows over the storage-taint pipeline.

    Returns the number of new rows inserted into ``flows``. No-ops when the
    storage-taint pipeline has not run (no ``storage_taint`` rows, or the
    table itself is missing).
    """
    for required in ("storage_taint", "storage_reads", "flows", "symbols"):
        if not _table_exists(conn, required):
            log.debug("stored_xss: skipping — table %s missing", required)
            return 0

    dirty = conn.execute(
        "SELECT storage_id, derived_tid, contributing_tids_json FROM storage_taint"
    ).fetchall()
    if not dirty:
        return 0

    existing_fids = {row[0] for row in conn.execute("SELECT fid FROM flows").fetchall()}
    inserted = 0
    for storage_id, derived_tid, contributing_json in dirty:
        try:
            contributing = [str(t) for t in json.loads(contributing_json or "[]")]
        except json.JSONDecodeError:
            contributing = []

        reads = _read_files(conn, str(storage_id))
        if not reads:
            continue

        origin = _origin_step(conn, contributing)

        for read_symbol, read_file in reads:
            xss_flows = _xss_flows_in_file(conn, read_file)
            if not xss_flows:
                continue

            for xss_fid, xss_steps_json, _xss_tid in xss_flows:
                fid = _stable_id("f-sxss-", str(storage_id), read_symbol, xss_fid)
                if fid in existing_fids:
                    continue

                try:
                    xss_steps = json.loads(xss_steps_json or "[]")
                except json.JSONDecodeError:
                    xss_steps = []
                xss_sink_step = xss_steps[-1] if xss_steps else [read_file, 0, 0]
                # Pull a representative write-site coordinate from any
                # storage_writes flow for this id; falling back to the
                # storage_id string is honest (the write happened somewhere
                # in the write-flow's CPG).
                write_row = conn.execute(
                    """
                    SELECT f.steps_json FROM storage_writes w
                    JOIN flows f ON f.fid = w.flow_id
                    WHERE w.storage_id = ?
                    LIMIT 1
                    """,
                    [storage_id],
                ).fetchone()
                write_step: list[Any] = [f"write:{storage_id}", 0, 0]
                if write_row and write_row[0]:
                    try:
                        ws = json.loads(write_row[0])
                    except json.JSONDecodeError:
                        ws = []
                    if ws and isinstance(ws[-1], list):
                        write_step = list(ws[-1])

                read_step = [read_file, 0, 0]
                steps = [origin, write_step, read_step, xss_sink_step]

                # Synthetic sid is keyed on the chain so re-runs don't churn.
                sid = _stable_id("S-sxss-", str(storage_id), read_symbol, xss_fid)
                conn.execute(
                    "INSERT OR IGNORE INTO taint_sinks VALUES (?, ?, ?, ?, ?, ?)",
                    [sid, None, "html.write", SYNTHETIC_ENGINE, "stored", "[]"],
                )

                conn.execute(
                    "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        fid,
                        derived_tid,
                        sid,
                        "CWE-79",
                        SYNTHETIC_ENGINE,
                        json.dumps(steps),
                        None,
                        "inferred",
                    ],
                )
                existing_fids.add(fid)
                inserted += 1
    return inserted
