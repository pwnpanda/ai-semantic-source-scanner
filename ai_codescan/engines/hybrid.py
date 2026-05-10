"""Hybrid engine: run CodeQL + Semgrep + Joern (when available) and dedupe.

Dedupe key: ``(source_file, source_line, sink_file, sink_line, cwe)``. When
multiple engines produce the same flow, we keep the highest-confidence record
and remember the union of engines in the ``engine`` column (e.g.
``codeql+semgrep``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
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
_CONFIDENCE_BY_RANK: dict[int, str] = {v: k for k, v in _CONFIDENCE_RANK.items()}

_CONSENSUS_FORCE_DEFINITE = 3
_CONSENSUS_BUMP_ONE_RANK = 2


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
        merged_conf = _consensus_confidence(
            base_confidence=survivor[7] or "unknown",
            engine_count=len(engines),
        )
        conn.execute(
            "UPDATE flows SET engine = ?, confidence = ? WHERE fid = ?",
            [merged_engine, merged_conf, survivor[0]],
        )
        for loser in group[1:]:
            conn.execute("DELETE FROM flows WHERE fid = ?", [loser[0]])
            removed += 1
    return removed


def _consensus_confidence(*, base_confidence: str, engine_count: int) -> str:
    """Boost confidence based on multi-engine agreement.

    - 1 engine → unchanged.
    - 2 engines → bump one rank (caps at 'definite').
    - 3+ engines → forced to 'definite'.
    """
    if engine_count >= _CONSENSUS_FORCE_DEFINITE:
        return "definite"
    if engine_count == _CONSENSUS_BUMP_ONE_RANK:
        rank = _CONFIDENCE_RANK.get(base_confidence, 0) + 1
        rank = min(rank, _CONFIDENCE_RANK["definite"])
        return _CONFIDENCE_BY_RANK.get(rank, base_confidence)
    return base_confidence


def _count_flows(conn: duckdb.DuckDBPyConnection, *, engine_like: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM flows WHERE engine LIKE ?",
        [engine_like],
    ).fetchone()
    return int(row[0]) if row else 0


def _stable_id(prefix: str, *parts: str) -> str:
    blob = "|".join(parts)
    return f"{prefix}:{hashlib.sha1(blob.encode('utf-8'), usedforsecurity=False).hexdigest()[:16]}"


def _ingest_joern_jsonl(  # noqa: PLR0913 - keyword-only fan-in is the cleanest expression here
    conn: duckdb.DuckDBPyConnection,
    *,
    jsonl_path: Path,
    project_id: str,
    snapshot_root: Path,
    project_root: Path | None = None,
) -> int:
    """Read Joern's JSONL output and merge into the ``flows`` table.

    Joern records are intentionally simpler than SARIF: a flat dict per flow
    with source/sink file:line, names, CWE, and sink_class. We build matching
    ``taint_sources``, ``taint_sinks``, and ``flows`` rows under
    ``engine='joern'`` so the dedupe pass can collapse duplicates against
    CodeQL/Semgrep.

    Joern emits source/sink paths relative to the **project root** it parsed
    (passed as ``project_root``), not the snapshot root. In a polyglot repo
    where a parent project (e.g. a React app at the repo root) and a nested
    project (``functions/`` Cloud Functions) overlap, scanning both produces
    the same flow under two different relative paths — which then keys
    differently in dedupe and shows up as duplicates. Canonicalising every
    path against ``snapshot_root`` (resolving ``project_root`` first) makes
    the absolute path stable regardless of which project's run produced it.
    """
    flows = joern_eng.parse_flows(jsonl_path)
    base = project_root if project_root is not None else snapshot_root
    inserted = 0
    for f in flows:
        source_file = str(f.get("source_file") or "")
        source_line_raw = f.get("source_line")
        source_line = int(source_line_raw) if isinstance(source_line_raw, int | str) else 0
        sink_file = str(f.get("sink_file") or "")
        sink_line_raw = f.get("sink_line")
        sink_line = int(sink_line_raw) if isinstance(sink_line_raw, int | str) else 0
        cwe = str(f.get("cwe") or "")
        sink_class = str(f.get("sink_class") or "unknown")
        sink_name = str(f.get("sink_name") or "")
        # Resolve relative paths against the project's own root so flows from
        # nested projects collapse with overlapping flows from the parent
        # project. ``str(Path(...).resolve())`` collapses any ``..`` /
        # symlinks too.
        if not source_file.startswith("/"):
            source_file = str((base / source_file).resolve())
        if not sink_file.startswith("/"):
            sink_file = str((base / sink_file).resolve())

        # ``project_id`` deliberately omitted from the stable-id keys so
        # cross-project duplicates collapse on identical (file, line)
        # tuples rather than fanning out per project.
        tid = _stable_id("source", source_file, str(source_line), cwe)
        sid = _stable_id("sink", sink_file, str(sink_line), sink_name)
        fid = str(f.get("fid") or _stable_id("flow", tid, sid))

        evidence_loc = f"{source_file}:{source_line}"
        conn.execute(
            "INSERT OR REPLACE INTO taint_sources VALUES (?, ?, ?, ?, ?)",
            [
                tid,
                None,
                "tainted-input",
                str(f.get("source_name") or ""),
                evidence_loc,
            ],
        )
        conn.execute(
            "INSERT OR REPLACE INTO taint_sinks VALUES (?, ?, ?, ?, ?, ?)",
            [sid, None, sink_class, sink_name, str(f.get("parameterization") or "unknown"), "[]"],
        )
        steps_json = json.dumps(
            [
                [source_file, source_line, source_line],
                [sink_file, sink_line, sink_line],
            ]
        )
        conn.execute(
            "INSERT OR REPLACE INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [fid, tid, sid, cwe, "joern", steps_json, str(jsonl_path), "inferred"],
        )
        inserted += 1
    return inserted


def run_hybrid(
    project_roots: list[tuple[Path, str, str]],
    *,
    snapshot_root: Path,
    repo_dir: Path,
    db_path: Path,
) -> HybridStats:
    """Drive Semgrep (and Joern when available) and dedupe.

    Each ``project_roots`` entry is ``(root_path, project_id, language)``;
    ``language`` is one of ``"javascript"`` or ``"python"`` and routes to the
    matching Joern frontend. CodeQL is expected to have already populated the
    flows table via the standard prep stage. This function adds Semgrep + Joern
    flows and runs the dedupe pass.
    """
    conn = duckdb.connect(str(db_path))
    try:
        codeql_flows = _count_flows(conn, engine_like="codeql%")
        semgrep_flows = 0
        joern_flows = 0

        for project_root, project_id, language in project_roots:
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
                    jsonl_path = joern_eng.run_joern(
                        project_root,
                        cache_dir=repo_dir,
                        project_id=project_id,
                        language=language,
                    )
                    joern_flows += _ingest_joern_jsonl(
                        conn,
                        jsonl_path=jsonl_path,
                        project_id=project_id,
                        snapshot_root=snapshot_root,
                        project_root=project_root,
                    )
                except joern_eng.JoernUnavailableError as exc:
                    log.warning("joern skipped for %s: %s", project_id, exc)
                except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                    log.warning("joern failed for %s: %s", project_id, exc)

        deduped = dedupe_flows(conn)
    finally:
        conn.close()

    return HybridStats(
        codeql_flows=codeql_flows,
        semgrep_flows=semgrep_flows,
        joern_flows=joern_flows,
        deduped=deduped,
    )
