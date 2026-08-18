"""Drive the deep_analyzer skill end-to-end."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import duckdb

from ai_codescan.evidence import build_evidence_bundle, truncate_bundle_to, write_evidence_bundle
from ai_codescan.findings.queue import (
    QueueItem,
    accepted_nominations_to_queue,
    render_queue,
)
from ai_codescan.llm import LLMConfig, is_available
from ai_codescan.nominator import write_llm_cmd_script
from ai_codescan.review_cache import build_llm_context_fingerprint
from ai_codescan.review_verdicts import sync_review_verdicts
from ai_codescan.runs.state import RunState, save
from ai_codescan.slice import extract_slice

SKILL_DIR = Path(__file__).resolve().parent / "skills" / "deep_analyzer"


@dataclass(frozen=True, slots=True)
class ReviewLimits:
    min_score: float = 0.0
    max_candidates: int | None = None
    max_bundle_bytes: int | None = None
    deterministic_only: bool = False


def _pick_flow_for_nomination(conn: duckdb.DuckDBPyConnection, nomination: dict) -> str | None:
    """Return the fid of the flow whose source location matches the nomination,
    falling back to None when no flow is found.
    """
    # 1. If the queue item is Stream A and already carries `fid`, use it directly.
    if nomination.get("stream") == "A" and nomination.get("fid"):
        return str(nomination["fid"])
    # 2. If we have an explicit source_loc, do an exact match.
    src_loc = nomination.get("source_loc") or ""
    if src_loc:
        row = conn.execute(
            "SELECT f.fid FROM flows f "
            "JOIN taint_sources s ON s.tid = f.tid "
            "WHERE s.evidence_loc = ? LIMIT 1",
            [src_loc],
        ).fetchone()
        if row:
            return str(row[0])
    # 3. Last-resort: the original loose match by file substring (Stream B nominations
    #    don't have an exact source_loc; we deliberately keep this fallback).
    file_hint = nomination.get("file") or src_loc.rsplit(":", 1)[0]
    if file_hint:
        row = conn.execute(
            "SELECT f.fid FROM flows f "
            "JOIN taint_sources s ON s.tid = f.tid "
            "WHERE s.evidence_loc LIKE ? LIMIT 1",
            [f"{file_hint}:%"],
        ).fetchone()
        if row:
            return str(row[0])
    return None


def _loc_parts(loc: str) -> tuple[str, int] | None:
    file, sep, raw_line = loc.rpartition(":")
    if not sep:
        return None
    try:
        return (file, int(raw_line))
    except ValueError:
        return None


def _score_for_items(
    conn: duckdb.DuckDBPyConnection,
    items: list[QueueItem],
) -> dict[str, float]:
    if not items:
        return {}
    wanted = {item.nomination_id for item in items}
    rows = conn.execute(
        """
        SELECT candidate_id, score
        FROM candidate_scores
        """,
    ).fetchall()
    return {
        str(candidate_id): float(score or 0.0)
        for candidate_id, score in rows
        if str(candidate_id) in wanted
    }


def _limit_review_items(
    conn: duckdb.DuckDBPyConnection,
    items: list[QueueItem],
    *,
    min_score: float = 0.0,
    max_candidates: int | None = None,
) -> list[QueueItem]:
    """Optionally cap LLM review work without hiding recorded candidates."""
    if min_score <= 0.0 and max_candidates is None:
        return items
    scores = _score_for_items(conn, items)
    filtered = [
        item
        for item in items
        if item.nomination_id not in scores or scores[item.nomination_id] >= min_score
    ]
    if max_candidates is None:
        return filtered
    return sorted(
        filtered,
        key=lambda item: (scores.get(item.nomination_id, 0.0), item.nomination_id),
        reverse=True,
    )[:max_candidates]


def _stage_slices(
    state: RunState,
    conn: duckdb.DuckDBPyConnection,
    items: list[QueueItem],
    *,
    source_root: Path,
    max_bundle_bytes: int | None = None,
) -> dict[str, int]:
    """Write compatibility slices and generalized evidence bundles for queue items.

    When `max_bundle_bytes` is set, each bundle is truncated to fit (excerpts and
    score factors are progressively shrunk; the bundle is annotated as truncated).
    Candidates are NEVER dropped here — Recall-First Invariant 4 forbids skipping
    candidates based on bundle size.
    """
    slices_dir = state.run_dir / "slices"
    slices_dir.mkdir(exist_ok=True)
    bundles_dir = state.run_dir / "bundles"
    bundle_sizes: dict[str, int] = {}
    for it in items:
        flow_id = _pick_flow_for_nomination(conn, {"source_loc": it.loc})
        # Mixed value types: ids and locations are strings, "line" is an int.
        candidate: dict[str, Any] = {
            "id": it.nomination_id,
            "stream": "A" if flow_id else "B",
            "fid": flow_id,
            "source_loc": it.loc,
        }
        if parsed := _loc_parts(it.loc):
            candidate["file"] = parsed[0]
            candidate["line"] = parsed[1]
        evidence = build_evidence_bundle(conn, candidate, source_root=source_root)
        if max_bundle_bytes is not None:
            evidence = truncate_bundle_to(evidence, max_bytes=max_bundle_bytes)
        json_bundle_path, _md_bundle_path = write_evidence_bundle(evidence, bundles_dir=bundles_dir)
        bundle_sizes[it.nomination_id] = json_bundle_path.stat().st_size
        if flow_id:
            bundle = extract_slice(conn, flow_id=flow_id, source_root=source_root)
            if bundle:
                (slices_dir / f"{it.nomination_id}.json").write_text(
                    json.dumps(
                        {
                            "flow_id": bundle.flow_id,
                            "cwe": bundle.cwe,
                            "source_loc": bundle.source_loc,
                            "sink_id": bundle.sink_id,
                            "steps": [asdict(step) for step in bundle.steps],
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
    return bundle_sizes


def run_analyzer(
    state: RunState,
    *,
    repo_dir: Path,
    db_path: Path,
    llm: LLMConfig | None = None,
    limits: ReviewLimits | None = None,
) -> Path:
    """Build the queue, stage slices, drive the deep-analyzer skill."""
    limits = limits or ReviewLimits()
    nominations = state.run_dir / "nominations.md"
    if not nominations.is_file():
        raise FileNotFoundError(f"no nominations.md at {nominations}")

    accepted = accepted_nominations_to_queue(nominations.read_text(encoding="utf-8"))

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        review_items = _limit_review_items(
            conn,
            accepted,
            min_score=limits.min_score,
            max_candidates=limits.max_candidates,
        )
        queue_path = state.run_dir / "findings_queue.md"
        _stage_slices(
            state,
            conn,
            review_items,
            source_root=repo_dir / "source",
            max_bundle_bytes=limits.max_bundle_bytes,
        )
        queue_path.write_text(render_queue(review_items), encoding="utf-8")
    finally:
        conn.close()

    state.phase = "analyze"
    save(state)

    effective = llm or LLMConfig(provider=state.llm_provider, model=state.llm_model)
    findings_dir = state.run_dir / "findings"
    findings_dir.mkdir(exist_ok=True)

    if limits.deterministic_only or not is_available(effective.provider):
        # No CLI on PATH — skill loop is skipped; downstream commands still work.
        _ = repo_dir  # repo_dir reserved for future passes; suppress unused warning
        return queue_path

    cmd_script = write_llm_cmd_script(state.run_dir / ".llm-cmd-analyze.sh", effective)
    env = os.environ.copy()
    env["AI_CODESCAN_RUN_DIR"] = str(state.run_dir)
    env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
    env["AI_CODESCAN_LLM_CMD"] = str(cmd_script)
    env["AI_CODESCAN_SOURCE_ROOT"] = str(repo_dir / "source")
    env["AI_CODESCAN_LLM_CONTEXT"] = build_llm_context_fingerprint(
        effective,
        source_root=repo_dir / "source",
    )
    env["CLAUDE_NO_AUTO_REGISTER"] = "1"

    subprocess.run(  # noqa: S603 - argv-only, no shell
        ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
        env=env,
        check=True,
    )
    conn = duckdb.connect(str(db_path))
    try:
        sync_review_verdicts(conn, findings_dir)
    finally:
        conn.close()
    return queue_path
