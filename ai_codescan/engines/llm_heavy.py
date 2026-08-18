"""LLM-heavy engine: drive an LLM to walk taint flows itself.

This is a Phase 2E alternative to CodeQL for codebases CodeQL doesn't cover
well. The LLM gets ``Read`` / ``Grep`` / ``Glob`` over the read-only snapshot
plus ``repo.md`` and ``entrypoints.md``, and emits ``flows.jsonl`` that the
orchestrator ingests into the same DuckDB ``flows`` table with
``engine='llm-heavy'``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import cast

import duckdb

from ai_codescan.cache_state import scan_stage_for_inputs, set_scan_stage
from ai_codescan.llm import LLMConfig, is_available
from ai_codescan.nominator import write_llm_cmd_script
from ai_codescan.repo_lock import repo_scan_lock
from ai_codescan.runs.state import RunState

SKILL_DIR = Path(__file__).resolve().parent.parent / "skills" / "llm_heavy"
_MIN_FLOW_STEPS = 2


def _stable_id(prefix: str, *parts: str) -> str:
    blob = "|".join(parts)
    return f"{prefix}:{hashlib.sha1(blob.encode('utf-8'), usedforsecurity=False).hexdigest()[:16]}"


def _validated_location(value: object, *, label: str, line_number: int) -> dict:
    if not isinstance(value, dict):
        raise RuntimeError(f"llm-heavy line {line_number}: {label} must be an object")
    location = cast(dict[str, object], value)
    file = location.get("file")
    line = location.get("line")
    if not isinstance(file, str) or not file:
        raise RuntimeError(f"llm-heavy line {line_number}: {label}.file must be non-empty")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise RuntimeError(f"llm-heavy line {line_number}: {label}.line must be positive")
    return location


def _normalized_steps(value: object, *, line_number: int) -> list[list[object]]:
    if not isinstance(value, list) or len(value) < _MIN_FLOW_STEPS:
        raise RuntimeError(f"llm-heavy line {line_number}: steps must contain at least two items")
    normalized: list[list[object]] = []
    for index, step in enumerate(value, start=1):
        location = _validated_location(
            step,
            label=f"steps[{index}]",
            line_number=line_number,
        )
        normalized.append([location["file"], location["line"], location["line"]])
    return normalized


def _validated_flow(raw_line: str, *, line_number: int) -> dict:
    try:
        entry = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"llm-heavy line {line_number}: invalid JSON") from exc
    if not isinstance(entry, dict):
        raise RuntimeError(f"llm-heavy line {line_number}: flow must be an object")
    source = _validated_location(entry.get("source"), label="source", line_number=line_number)
    sink = _validated_location(entry.get("sink"), label="sink", line_number=line_number)
    for label, location in (("source", source), ("sink", sink)):
        if not isinstance(location.get("class"), str) or not location["class"]:
            raise RuntimeError(f"llm-heavy line {line_number}: {label}.class must be non-empty")
    cwe = entry.get("cwe")
    if not isinstance(cwe, str) or not cwe.startswith("CWE-") or not cwe[4:].isdigit():
        raise RuntimeError(f"llm-heavy line {line_number}: cwe must use CWE-<number>")
    entry["steps"] = _normalized_steps(entry.get("steps"), line_number=line_number)
    return entry


def _load_validated_flows(flows_path: Path) -> list[dict]:
    entries: list[dict] = []
    for line_number, raw_line in enumerate(
        flows_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if raw_line.strip():
            entries.append(_validated_flow(raw_line, line_number=line_number))
    return entries


def ingest_llm_heavy_flows(
    conn: duckdb.DuckDBPyConnection,
    *,
    flows_path: Path,
    sarif_ref: str = "",
) -> int:
    """Read ``flows_path`` (JSONL) and insert each flow into DuckDB. Returns count."""
    if not flows_path.is_file():
        return 0
    entries = _load_validated_flows(flows_path)
    inserted = 0
    for entry in entries:
        source = entry.get("source", {})
        sink = entry.get("sink", {})
        cwe = entry.get("cwe")
        sid = entry.get("sid") or _stable_id(
            "sink",
            sink.get("file", ""),
            str(sink.get("line", 0)),
            sink.get("class", ""),
        )
        tid = entry.get("tid") or _stable_id(
            "source",
            source.get("file", ""),
            str(source.get("line", 0)),
            source.get("class", ""),
        )
        fid = entry.get("fid") or _stable_id("flow", tid, sid)
        conn.execute(
            "INSERT OR REPLACE INTO taint_sinks VALUES (?, ?, ?, ?, ?, ?)",
            [sid, None, sink.get("class", "unknown"), sink.get("lib"), "unknown", "[]"],
        )
        conn.execute(
            "INSERT OR REPLACE INTO taint_sources VALUES (?, ?, ?, ?, ?)",
            [
                tid,
                None,
                source.get("class", "unknown"),
                source.get("key"),
                f"{source.get('file', '')}:{source.get('line', 0)}",
            ],
        )
        steps_json = json.dumps(entry.get("steps", []))
        confidence = entry.get("confidence", "inferred")
        conn.execute(
            "INSERT OR REPLACE INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [fid, tid, sid, cwe, "llm-heavy", steps_json, sarif_ref, confidence],
        )
        inserted += 1
    return inserted


def _llm_prep_generation(
    repo_dir: Path,
    *,
    db_path: Path,
    scan_fingerprint: str | None = None,
) -> tuple[int | None, bool]:
    if scan_fingerprint is None:
        return None, False
    if (repo_dir / ".prep-incomplete").is_file():
        raise RuntimeError("llm-heavy stage refused: prep is incomplete")
    conn = duckdb.connect(str(db_path))
    try:
        stage = scan_stage_for_inputs(
            conn,
            fingerprint=scan_fingerprint,
            engine="llm-heavy",
        )
        if stage == "complete":
            row = conn.execute("SELECT COUNT(*) FROM flows WHERE engine = 'llm-heavy'").fetchone()
            return (int(row[0]) if row else 0), False
        if stage not in {"prep", "prep_with_gaps"}:
            raise RuntimeError("llm-heavy stage refused: no matching completed prep generation")
        return None, stage == "prep_with_gaps"
    finally:
        conn.close()


def _run_llm_walker(
    state: RunState,
    *,
    repo_dir: Path,
    target_bug_classes: list[str] | None,
    llm: LLMConfig | None,
) -> Path:
    inputs_dir = state.run_dir / "inputs"
    inputs_dir.mkdir(exist_ok=True)
    if (repo_dir / "repo.md").is_file():
        shutil.copyfile(repo_dir / "repo.md", inputs_dir / "repo.md")
    if (repo_dir / "entrypoints.md").is_file():
        shutil.copyfile(repo_dir / "entrypoints.md", inputs_dir / "entrypoints.md")

    flows_path = state.run_dir / "llm_heavy_flows.jsonl"
    flows_path.write_text("", encoding="utf-8")
    effective = llm or LLMConfig(provider=state.llm_provider, model=state.llm_model)
    if not is_available(effective.provider):
        raise RuntimeError(
            f"requested LLM provider '{effective.provider}' is not available on PATH"
        )
    source_root = repo_dir / "source"
    if not source_root.is_dir():
        raise RuntimeError(f"source snapshot is missing for llm-heavy: {source_root}")
    cmd_script = write_llm_cmd_script(state.run_dir / ".llm-cmd-llm-heavy.sh", effective)
    env = os.environ.copy()
    env["AI_CODESCAN_RUN_DIR"] = str(state.run_dir)
    env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
    env["AI_CODESCAN_LLM_CMD"] = str(cmd_script)
    env["AI_CODESCAN_SOURCE_ROOT"] = str(source_root)
    env["AI_CODESCAN_TARGET_BUG_CLASSES"] = ",".join(target_bug_classes or [])
    env["CLAUDE_NO_AUTO_REGISTER"] = "1"
    subprocess.run(  # noqa: S603 - argv-only, no shell
        ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
        env=env,
        cwd=source_root,
        check=True,
    )
    return flows_path


def _persist_llm_flows(
    db_path: Path,
    *,
    flows_path: Path,
    scan_fingerprint: str | None,
    base_has_gaps: bool,
    model_is_pinned: bool,
) -> int:
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute("BEGIN TRANSACTION")
        count = ingest_llm_heavy_flows(conn, flows_path=flows_path)
        if scan_fingerprint:
            completion_stage = "complete"
            if base_has_gaps:
                completion_stage = "complete_with_gaps"
            elif not model_is_pinned:
                completion_stage = "complete_unpinned"
            set_scan_stage(
                conn,
                fingerprint=scan_fingerprint,
                engine="llm-heavy",
                stage=completion_stage,
            )
        conn.execute("COMMIT")
        return count
    except BaseException:
        with suppress(duckdb.Error):
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def run_llm_heavy_engine(  # noqa: PLR0913 - one positional arg; remaining knobs are keyword-only
    state: RunState,
    *,
    repo_dir: Path,
    db_path: Path,
    target_bug_classes: list[str] | None = None,
    llm: LLMConfig | None = None,
    scan_fingerprint: str | None = None,
) -> int:
    """Drive the llm_heavy skill, then ingest its emitted flows.jsonl. Returns flow count."""
    with repo_scan_lock(repo_dir):
        cached_count, base_has_gaps = _llm_prep_generation(
            repo_dir,
            db_path=db_path,
            scan_fingerprint=scan_fingerprint,
        )
        if cached_count is not None:
            return cached_count
        flows_path = _run_llm_walker(
            state,
            repo_dir=repo_dir,
            target_bug_classes=target_bug_classes,
            llm=llm,
        )
        return _persist_llm_flows(
            db_path,
            flows_path=flows_path,
            scan_fingerprint=scan_fingerprint,
            base_has_gaps=base_has_gaps,
            model_is_pinned=bool((llm or LLMConfig(state.llm_provider, state.llm_model)).model),
        )
