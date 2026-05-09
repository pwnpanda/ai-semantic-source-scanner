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
from pathlib import Path

import duckdb

from ai_codescan.llm import LLMConfig, is_available
from ai_codescan.nominator import write_llm_cmd_script
from ai_codescan.runs.state import RunState

SKILL_DIR = Path(__file__).resolve().parent.parent / "skills" / "llm_heavy"


def _stable_id(prefix: str, *parts: str) -> str:
    blob = "|".join(parts)
    return f"{prefix}:{hashlib.sha1(blob.encode('utf-8'), usedforsecurity=False).hexdigest()[:16]}"


def ingest_llm_heavy_flows(
    conn: duckdb.DuckDBPyConnection,
    *,
    flows_path: Path,
    sarif_ref: str = "",
) -> int:
    """Read ``flows_path`` (JSONL) and insert each flow into DuckDB. Returns count."""
    if not flows_path.is_file():
        return 0
    inserted = 0
    for raw_line in flows_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
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


def run_llm_heavy_engine(
    state: RunState,
    *,
    repo_dir: Path,
    db_path: Path,
    target_bug_classes: list[str] | None = None,
    llm: LLMConfig | None = None,
) -> int:
    """Drive the llm_heavy skill, then ingest its emitted flows.jsonl. Returns flow count."""
    inputs_dir = state.run_dir / "inputs"
    inputs_dir.mkdir(exist_ok=True)
    if (repo_dir / "repo.md").is_file():
        shutil.copyfile(repo_dir / "repo.md", inputs_dir / "repo.md")
    if (repo_dir / "entrypoints.md").is_file():
        shutil.copyfile(repo_dir / "entrypoints.md", inputs_dir / "entrypoints.md")

    flows_path = state.run_dir / "llm_heavy_flows.jsonl"
    flows_path.write_text("", encoding="utf-8")

    effective = llm or LLMConfig(provider=state.llm_provider, model=state.llm_model)
    if is_available(effective.provider):
        cmd_script = write_llm_cmd_script(state.run_dir / ".llm-cmd-llm-heavy.sh", effective)
        env = os.environ.copy()
        env["AI_CODESCAN_RUN_DIR"] = str(state.run_dir)
        env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
        env["AI_CODESCAN_LLM_CMD"] = str(cmd_script)
        env["AI_CODESCAN_TARGET_BUG_CLASSES"] = ",".join(target_bug_classes or [])
        subprocess.run(  # noqa: S603 - argv-only, no shell
            ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
            env=env,
            check=False,
        )

    conn = duckdb.connect(str(db_path))
    try:
        return ingest_llm_heavy_flows(conn, flows_path=flows_path)
    finally:
        conn.close()
