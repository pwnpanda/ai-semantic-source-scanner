"""Hybrid engine: run CodeQL + Semgrep + Joern (when available) and dedupe.

Dedupe key: ``(source_file, source_line, sink_file, sink_line, cwe)``. When
multiple engines produce the same flow, we keep the highest-confidence record
and remember the union of engines in the ``engine`` column (e.g.
``codeql+semgrep``).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import duckdb

from ai_codescan.engines import joern as joern_eng
from ai_codescan.engines import semgrep as semgrep_eng
from ai_codescan.ingest.sarif import ingest_sarif

log = logging.getLogger(__name__)

_MIN_STEPS_FOR_KEY = 2

_CONFIDENCE_RANK: dict[str, int] = {
    "definite": 3,
    "inferred": 2,
    "llm-suggested": 1,
    "unknown": 0,
}


@dataclass(frozen=True, slots=True)
class HybridStats:
    codeql_flows: int
    semgrep_flows: int
    joern_flows: int
    deduped: int


def _flow_key(steps_json: str, cwe: str | None) -> tuple[str, int, str, int, str]:
    steps = json.loads(steps_json or "[]")
    if len(steps) < _MIN_STEPS_FOR_KEY:
        return ("", 0, "", 0, cwe or "")
    src = steps[0]
    sink = steps[-1]
    return (
        str(src[0]) if len(src) > 0 else "",
        int(src[1]) if len(src) > 1 else 0,
        str(sink[0]) if len(sink) > 0 else "",
        int(sink[1]) if len(sink) > 1 else 0,
        cwe or "",
    )


def dedupe_flows(conn: duckdb.DuckDBPyConnection) -> int:
    """Collapse rows with the same source-line/sink-line/cwe key.

    Strategy: keep the row with the highest confidence; when two rows from
    different engines share the same key, set the survivor's ``engine`` column
    to ``"<eng1>+<eng2>"`` (sorted, dedup'd) so consumers see provenance.
    Returns the number of rows removed.
    """
    rows = conn.execute(
        "SELECT fid, tid, sid, cwe, engine, steps_json, sarif_ref, confidence FROM flows"
    ).fetchall()
    by_key: dict[tuple[str, int, str, int, str], list[tuple]] = {}
    for row in rows:
        key = _flow_key(row[5] or "", row[3])
        by_key.setdefault(key, []).append(row)

    removed = 0
    for group in by_key.values():
        if len(group) <= 1:
            continue
        group.sort(key=lambda r: _CONFIDENCE_RANK.get(r[7] or "unknown", 0), reverse=True)
        survivor = group[0]
        engines = sorted({r[4] for r in group if r[4]})
        merged_engine = "+".join(engines) if len(engines) > 1 else (survivor[4] or "")
        conn.execute(
            "UPDATE flows SET engine = ? WHERE fid = ?",
            [merged_engine, survivor[0]],
        )
        for loser in group[1:]:
            conn.execute("DELETE FROM flows WHERE fid = ?", [loser[0]])
            removed += 1
    return removed


def _count_flows(conn: duckdb.DuckDBPyConnection, *, engine_like: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM flows WHERE engine LIKE ?",
        [engine_like],
    ).fetchone()
    return int(row[0]) if row else 0


def run_hybrid(
    project_roots: list[tuple[Path, str]],
    *,
    snapshot_root: Path,
    repo_dir: Path,
    db_path: Path,
) -> HybridStats:
    """Drive Semgrep (and Joern when available) and dedupe.

    CodeQL is expected to have already populated the flows table via the
    standard prep stage. This function adds Semgrep + Joern flows and runs
    the dedupe pass.
    """
    conn = duckdb.connect(str(db_path))
    try:
        codeql_flows = _count_flows(conn, engine_like="codeql%")
        semgrep_flows = 0
        joern_flows = 0

        for project_root, project_id in project_roots:
            if semgrep_eng.is_available():
                try:
                    sarif_path = semgrep_eng.run_semgrep(
                        project_root, cache_dir=repo_dir, project_id=project_id
                    )
                    semgrep_flows += ingest_sarif(
                        conn,
                        sarif_path=sarif_path,
                        project_id=project_id,
                        snapshot_root=snapshot_root,
                        engine="semgrep",
                    )
                except (RuntimeError, OSError) as exc:
                    log.warning("semgrep failed for %s: %s", project_id, exc)

            if joern_eng.is_available():
                try:
                    joern_eng.run_joern(
                        project_root, cache_dir=repo_dir, project_id=project_id
                    )
                    # Joern integration stub — real ingest lands when the .sc
                    # query is implemented (see joern.py docstring).
                except joern_eng.JoernUnavailableError as exc:
                    log.warning("joern skipped for %s: %s", project_id, exc)

        deduped = dedupe_flows(conn)
    finally:
        conn.close()

    return HybridStats(
        codeql_flows=codeql_flows,
        semgrep_flows=semgrep_flows,
        joern_flows=joern_flows,
        deduped=deduped,
    )
