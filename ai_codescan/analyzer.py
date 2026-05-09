"""Drive the deep_analyzer skill end-to-end."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict
from pathlib import Path

import duckdb

from ai_codescan.findings.queue import (
    QueueItem,
    accepted_nominations_to_queue,
    render_queue,
)
from ai_codescan.llm import LLMConfig, is_available
from ai_codescan.nominator import write_llm_cmd_script
from ai_codescan.runs.state import RunState, save
from ai_codescan.slice import extract_slice

SKILL_DIR = Path(__file__).resolve().parent / "skills" / "deep_analyzer"


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


def _stage_slices(state: RunState, conn: duckdb.DuckDBPyConnection, items: list[QueueItem]) -> int:
    """Write one slices/<nomination_id>.json per item that resolves to a known flow."""
    slices_dir = state.run_dir / "slices"
    slices_dir.mkdir(exist_ok=True)
    written = 0
    for it in items:
        flow_id = _pick_flow_for_nomination(conn, {"source_loc": it.loc})
        if not flow_id:
            continue
        bundle = extract_slice(conn, flow_id=flow_id)
        if not bundle:
            continue
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
        written += 1
    return written


def run_analyzer(
    state: RunState,
    *,
    repo_dir: Path,
    db_path: Path,
    llm: LLMConfig | None = None,
) -> Path:
    """Build the queue, stage slices, drive the deep-analyzer skill."""
    nominations = state.run_dir / "nominations.md"
    if not nominations.is_file():
        raise FileNotFoundError(f"no nominations.md at {nominations}")

    accepted = accepted_nominations_to_queue(nominations.read_text(encoding="utf-8"))
    queue_path = state.run_dir / "findings_queue.md"
    queue_path.write_text(render_queue(accepted), encoding="utf-8")

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        _stage_slices(state, conn, accepted)
    finally:
        conn.close()

    state.phase = "analyze"
    save(state)

    effective = llm or LLMConfig(provider=state.llm_provider, model=state.llm_model)
    findings_dir = state.run_dir / "findings"
    findings_dir.mkdir(exist_ok=True)

    if not is_available(effective.provider):
        # No CLI on PATH — skill loop is skipped; downstream commands still work.
        _ = repo_dir  # repo_dir reserved for future passes; suppress unused warning
        return queue_path

    cmd_script = write_llm_cmd_script(state.run_dir / ".llm-cmd-analyze.sh", effective)
    env = os.environ.copy()
    env["AI_CODESCAN_RUN_DIR"] = str(state.run_dir)
    env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
    env["AI_CODESCAN_LLM_CMD"] = str(cmd_script)

    subprocess.run(  # noqa: S603 - argv-only, no shell
        ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
        env=env,
        check=True,
    )
    return queue_path
