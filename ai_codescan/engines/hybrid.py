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
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import duckdb

from ai_codescan.artifact_id import normalize_artifact_id
from ai_codescan.cache_state import scan_stage_for_inputs, set_scan_stage
from ai_codescan.engines import joern as joern_eng
from ai_codescan.engines import semgrep as semgrep_eng
from ai_codescan.ingest.sarif import ingest_sarif
from ai_codescan.repo_lock import repo_scan_lock
from ai_codescan.source_paths import resolve_contained_file

log = logging.getLogger(__name__)

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
    reused: bool = False


class HybridStageError(RuntimeError):
    """Raised when an available hybrid engine fails for any project."""


def _flow_key(steps_json: str, cwe: str | None) -> tuple[str, int, str, int, str]:
    steps = json.loads(steps_json or "[]")
    if not steps:
        return ("", 0, "", 0, cwe or "")
    # A pattern-only finding (Semgrep ``patterns`` mode, CodeQL ``problem``
    # queries) has a single step that is both source and sink. Keying those
    # on the degenerate empty tuple collapsed every pattern finding sharing a
    # CWE into one row, no matter which file or line it came from.
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
            conn.execute("DELETE FROM flow_metadata WHERE fid = ?", [loser[0]])
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


def _cached_stats(conn: duckdb.DuckDBPyConnection) -> HybridStats:
    return HybridStats(
        codeql_flows=_count_flows(conn, engine_like="%codeql%"),
        semgrep_flows=_count_flows(conn, engine_like="%semgrep%"),
        joern_flows=_count_flows(conn, engine_like="%joern%"),
        deduped=0,
        reused=True,
    )


def _run_project_engines(
    conn: duckdb.DuckDBPyConnection,
    *,
    project_roots: list[tuple[Path, str, str]],
    snapshot_root: Path,
    repo_dir: Path,
) -> tuple[int, int, list[str], bool]:
    semgrep_flows = 0
    joern_flows = 0
    failures: list[str] = []
    used_mutable_semgrep = False
    for project_root, raw_project_id, language in project_roots:
        project_id = normalize_artifact_id(raw_project_id)
        if semgrep_eng.is_available():
            used_mutable_semgrep = True
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
                failures.append(f"semgrep/{project_id}: {exc}")

        if not joern_eng.supports_language(language):
            # Perl has no Joern frontend. Semgrep's generic-mode rules above
            # are the only deterministic pass; interprocedural taint for this
            # project comes from the llm-heavy engine instead.
            log.info(
                "joern has no frontend for %s; skipping CPG build for %s", language, project_id
            )
        elif joern_eng.is_available():
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
                failures.append(f"joern/{project_id}: {exc}")
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                log.warning("joern failed for %s: %s", project_id, exc)
                failures.append(f"joern/{project_id}: {exc}")
    return semgrep_flows, joern_flows, failures, used_mutable_semgrep


def _stable_id(prefix: str, *parts: str) -> str:
    blob = "|".join(parts)
    return f"{prefix}:{hashlib.sha1(blob.encode('utf-8'), usedforsecurity=False).hexdigest()[:16]}"


def _normalize_joern_paths(
    flow: dict,
    *,
    snapshot_root: Path,
    base: Path,
) -> dict:
    """Return a Joern flow whose endpoint paths are canonical and contained."""
    source_file = resolve_contained_file(
        snapshot_root,
        str(flow.get("source_file") or ""),
        relative_to=base,
    )
    sink_file = resolve_contained_file(
        snapshot_root,
        str(flow.get("sink_file") or ""),
        relative_to=base,
    )
    return {
        **flow,
        "source_file": source_file.as_posix(),
        "sink_file": sink_file.as_posix(),
    }


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
    base = project_root if project_root is not None else snapshot_root
    flows = [
        _normalize_joern_paths(
            flow,
            snapshot_root=snapshot_root,
            base=base,
        )
        for flow in joern_eng.parse_flows(jsonl_path)
    ]
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
        flow_type = str(f.get("flow_type") or "dataflow")
        # Recall-First Invariant 2: mitigation patterns (e.g. canonicalisation +
        # root containment for CWE-22) DEMOTE candidates via score factors during
        # scoring. They MUST NOT suppress the flow at ingest. See
        # `ai_codescan/mitigations.detect_path_mitigations` and the
        # `mitigation_signal` factor in `ai_codescan/scoring.score_candidate`.

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
        # flow_type lives in a sidecar table so the existing 8-column INSERT
        # surface stays compatible (Recall-First Invariant 6 sidecar).
        conn.execute(
            "INSERT OR REPLACE INTO flow_metadata VALUES (?, ?)",
            [fid, flow_type],
        )
        inserted += 1
    return inserted


def _hybrid_stage_state(
    conn: duckdb.DuckDBPyConnection,
    *,
    scan_fingerprint: str | None,
) -> tuple[HybridStats | None, tuple[str, str] | None]:
    if scan_fingerprint is None:
        return None, None
    stage = scan_stage_for_inputs(
        conn,
        fingerprint=scan_fingerprint,
        engine="hybrid",
    )
    if stage == "complete":
        return _cached_stats(conn), None
    if stage not in {"prep", "prep_with_gaps"}:
        raise HybridStageError("hybrid stage refused: no matching completed prep generation")
    completion_stage = "complete_with_gaps" if stage == "prep_with_gaps" else "complete"
    return None, (scan_fingerprint, completion_stage)


def _record_hybrid_completion(
    conn: duckdb.DuckDBPyConnection,
    *,
    completion: tuple[str, str] | None,
    used_mutable_semgrep: bool,
) -> None:
    if completion is None:
        return
    scan_fingerprint, completion_stage = completion
    if completion_stage == "complete" and used_mutable_semgrep:
        completion_stage = "complete_unpinned"
    set_scan_stage(
        conn,
        fingerprint=scan_fingerprint,
        engine="hybrid",
        stage=completion_stage,
    )


def _run_hybrid_transaction(
    conn: duckdb.DuckDBPyConnection,
    *,
    project_roots: list[tuple[Path, str, str]],
    snapshot_root: Path,
    repo_dir: Path,
    completion: tuple[str, str] | None,
) -> HybridStats:
    conn.execute("BEGIN TRANSACTION")
    try:
        codeql_flows = _count_flows(conn, engine_like="codeql%")
        semgrep_flows, joern_flows, failures, mutable_semgrep = _run_project_engines(
            conn,
            project_roots=project_roots,
            snapshot_root=snapshot_root,
            repo_dir=repo_dir,
        )
        if failures:
            raise HybridStageError("hybrid stage incomplete: " + "; ".join(failures))
        deduped = dedupe_flows(conn)
        _record_hybrid_completion(
            conn,
            completion=completion,
            used_mutable_semgrep=mutable_semgrep,
        )
        conn.execute("COMMIT")
    except BaseException:
        with suppress(duckdb.Error):
            conn.execute("ROLLBACK")
        raise
    return HybridStats(
        codeql_flows=codeql_flows,
        semgrep_flows=semgrep_flows,
        joern_flows=joern_flows,
        deduped=deduped,
    )


def run_hybrid(
    project_roots: list[tuple[Path, str, str]],
    *,
    snapshot_root: Path,
    repo_dir: Path,
    db_path: Path,
    scan_fingerprint: str | None = None,
) -> HybridStats:
    """Drive Semgrep (and Joern when available) and dedupe.

    Each ``project_roots`` entry is ``(root_path, project_id, language)``. The
    language selects the matching supported Joern frontend. CodeQL is expected
    to have already populated the flows table via the standard prep stage. This
    function adds Semgrep + Joern flows and runs the dedupe pass.
    """
    with repo_scan_lock(repo_dir):
        if scan_fingerprint and (repo_dir / ".prep-incomplete").is_file():
            raise HybridStageError("hybrid stage refused: prep is incomplete")
        conn = duckdb.connect(str(db_path))
        try:
            cached, completion = _hybrid_stage_state(
                conn,
                scan_fingerprint=scan_fingerprint,
            )
            if cached is not None:
                return cached
            return _run_hybrid_transaction(
                conn,
                project_roots=project_roots,
                snapshot_root=snapshot_root,
                repo_dir=repo_dir,
                completion=completion,
            )
        finally:
            conn.close()
