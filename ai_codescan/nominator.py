"""Drive the wide_nominator skill end-to-end."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import duckdb

from ai_codescan.runs.state import RunState, save
from ai_codescan.taxonomy.loader import BugClass, resolve_classes

SKILL_DIR = Path(__file__).resolve().parent / "skills" / "wide_nominator"


def _cwes_for_classes(classes: list[BugClass]) -> set[str]:
    return {cwe for c in classes for cwe in c.cwes}


def build_queue(
    conn: duckdb.DuckDBPyConnection,
    *,
    target_bug_classes: list[str],
) -> list[dict[str, Any]]:
    """Return the ordered list of candidate descriptors for the skill loop."""
    selected = resolve_classes(target_bug_classes) if target_bug_classes else []
    cwes = _cwes_for_classes(selected) if selected else None

    queue: list[dict[str, Any]] = []
    flow_rows = conn.execute(
        """
        SELECT f.fid, f.tid, f.sid, f.cwe, f.engine, s.evidence_loc,
               t.class, t.lib, t.parameterization
        FROM flows f
        JOIN taint_sources s ON s.tid = f.tid
        JOIN taint_sinks   t ON t.sid = f.sid
        """
    ).fetchall()
    for fid, tid, sid, cwe, engine, evidence_loc, sink_class, lib, parameterization in flow_rows:
        if cwes is not None and cwe not in cwes:
            continue
        queue.append(
            {
                "id": f"A-{fid}",
                "stream": "A",
                "fid": fid,
                "tid": tid,
                "sid": sid,
                "cwe": cwe,
                "engine": engine,
                "source_loc": evidence_loc,
                "sink_class": sink_class,
                "lib": lib,
                "parameterization": parameterization,
            }
        )

    sink_no_flow = conn.execute(
        """
        SELECT sid, class, lib, parameterization
        FROM taint_sinks
        WHERE sid NOT IN (SELECT sid FROM flows)
        """
    ).fetchall()
    for sid, sink_class, lib, parameterization in sink_no_flow:
        queue.append(
            {
                "id": f"B-sink-{sid}",
                "stream": "B",
                "concern": "sink-without-source",
                "sink_id": sid,
                "sink_class": sink_class,
                "lib": lib,
                "parameterization": parameterization,
            }
        )

    auth_rows = conn.execute(
        """
        SELECT id, file, range_start, display_name
        FROM symbols
        WHERE display_name ILIKE '%authoriz%'
           OR display_name ILIKE '%authent%'
           OR display_name ILIKE '%permission%'
        """
    ).fetchall()
    for sym_id, file, line, name in auth_rows:
        queue.append(
            {
                "id": f"B-auth-{sym_id}",
                "stream": "B",
                "concern": "authz-callsite",
                "symbol_id": sym_id,
                "file": file,
                "line": line,
                "name": name,
            }
        )

    return queue


def _stage_inputs(
    state: RunState,
    repo_dir: Path,
    queue: list[dict[str, Any]],
) -> None:
    inputs = state.run_dir / "inputs"
    inputs.mkdir(exist_ok=True)
    shutil.copyfile(repo_dir / "repo.md", inputs / "repo.md")
    if (repo_dir / "entrypoints.md").is_file():
        shutil.copyfile(repo_dir / "entrypoints.md", inputs / "entrypoints.md")

    flows_path = inputs / "flows.jsonl"
    with flows_path.open("w", encoding="utf-8") as f:
        for q in queue:
            if q["stream"] == "A":
                f.write(json.dumps(q) + "\n")

    queue_path = state.run_dir / "queue.jsonl"
    with queue_path.open("w", encoding="utf-8") as f:
        for q in queue:
            f.write(json.dumps(q) + "\n")


def _empty_nominations_md() -> str:
    return (
        "# Nominations\n\n"
        "## Stream A — Pre-traced (CodeQL flows ready for triage)\n\n"
        "## Stream B — AI-discovered candidates (no static flow exists; semantic concern)\n\n"
        "## Stream C — Proposed CodeQL model extensions\n"
    )


def run_nominator(
    state: RunState,
    *,
    repo_dir: Path,
    bug_classes: list[BugClass],
    db_path: Path,
) -> Path:
    """Stage inputs, drive the skill loop, return path to nominations.md."""
    conn = duckdb.connect(str(db_path), read_only=True)
    queue = build_queue(
        conn,
        target_bug_classes=[c.name for c in bug_classes],
    )

    _stage_inputs(state, repo_dir, queue)
    state.phase = "nominate"
    save(state)

    nominations_path = state.run_dir / "nominations.md"

    if shutil.which("claude") is None:
        nominations_path.write_text(_empty_nominations_md(), encoding="utf-8")
        return nominations_path

    env = os.environ.copy()
    env["AI_CODESCAN_RUN_DIR"] = str(state.run_dir)
    env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
    env["AI_CODESCAN_TARGET_BUG_CLASSES"] = ",".join(c.name for c in bug_classes)

    subprocess.run(  # noqa: S603 - argv-only, no shell; bash is on PATH
        ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
        env=env,
        check=True,
    )
    return nominations_path
