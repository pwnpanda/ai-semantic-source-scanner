"""Extract a minimal flow slice (LLMxCPG pattern) for an LLM sub-agent."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import duckdb


@dataclass(frozen=True, slots=True)
class SliceStep:
    file: str
    line: int
    context_start: int
    context_end: int
    code_excerpt: str


_MIN_STEP_FIELDS = 2  # [file, start_line] minimum; end_line is optional


@dataclass(frozen=True, slots=True)
class SliceBundle:
    flow_id: str
    cwe: str | None
    source_loc: str
    sink_id: str
    steps: list[SliceStep]


def _read_excerpt(file: Path, start: int, end: int) -> str:
    if not file.is_file():
        return ""
    lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[max(0, start - 1) : end])


def extract_slice(
    conn: duckdb.DuckDBPyConnection,
    *,
    flow_id: str,
    context_lines: int = 5,
) -> SliceBundle | None:
    """Return a slice bundle for ``flow_id`` or ``None`` if the flow is unknown."""
    row = conn.execute(
        """
        SELECT f.fid, f.cwe, f.tid, f.sid, f.steps_json, s.evidence_loc
        FROM flows f
        JOIN taint_sources s ON s.tid = f.tid
        WHERE f.fid = ?
        """,
        [flow_id],
    ).fetchone()
    if row is None:
        return None
    fid, cwe, _tid, sid, steps_json, source_loc = row

    raw_steps: list[list] = json.loads(steps_json or "[]")
    steps: list[SliceStep] = []
    for entry in raw_steps:
        if len(entry) < _MIN_STEP_FIELDS:
            continue
        file_str = str(entry[0])
        start_line = int(entry[1])
        ctx_start = max(1, start_line - context_lines)
        ctx_end = start_line + context_lines
        excerpt = _read_excerpt(Path(file_str), ctx_start, ctx_end)
        n_lines_kept = len(excerpt.splitlines())
        actual_end = ctx_start + max(0, n_lines_kept - 1)
        steps.append(
            SliceStep(
                file=file_str,
                line=start_line,
                context_start=ctx_start,
                context_end=actual_end,
                code_excerpt=excerpt,
            )
        )

    return SliceBundle(
        flow_id=fid,
        cwe=cwe,
        source_loc=source_loc or "",
        sink_id=sid,
        steps=steps,
    )
