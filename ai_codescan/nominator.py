"""Drive the wide_nominator skill end-to-end."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import duckdb

from ai_codescan.evidence import build_evidence_bundle, write_evidence_bundle
from ai_codescan.llm import LLMConfig, build_argv, is_available
from ai_codescan.review_cache import build_llm_context_fingerprint
from ai_codescan.runs.state import RunState, save
from ai_codescan.scoring import attach_scores, persist_candidate_scores, score_candidates
from ai_codescan.taxonomy.loader import BugClass, resolve_classes

SKILL_DIR = Path(__file__).resolve().parent / "skills" / "wide_nominator"
_SAFE_CANDIDATE_COMPONENT = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_CANDIDATE_COMPONENT_LENGTH = 80
_CANDIDATE_COMPONENT_HASH_LENGTH = 16


def _candidate_id_component(value: object) -> str:
    component = str(value)
    if (
        component
        and len(component) <= _MAX_CANDIDATE_COMPONENT_LENGTH
        and _SAFE_CANDIDATE_COMPONENT.fullmatch(component)
    ):
        return component
    digest = hashlib.sha256(component.encode("utf-8")).hexdigest()
    return f"h-{digest[:_CANDIDATE_COMPONENT_HASH_LENGTH]}"


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
               t.class, t.lib, t.parameterization,
               COALESCE(m.flow_type, 'dataflow')
        FROM flows f
        JOIN taint_sources s ON s.tid = f.tid
        JOIN taint_sinks   t ON t.sid = f.sid
        LEFT JOIN flow_metadata m ON m.fid = f.fid
        """
    ).fetchall()
    for (
        fid,
        tid,
        sid,
        cwe,
        engine,
        evidence_loc,
        sink_class,
        lib,
        parameterization,
        flow_type,
    ) in flow_rows:
        if cwes is not None and cwe not in cwes:
            continue
        candidate_component = _candidate_id_component(fid)
        queue.append(
            {
                "id": f"A-{candidate_component}",
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
                "flow_type": flow_type,
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
        candidate_component = _candidate_id_component(sid)
        queue.append(
            {
                "id": f"B-sink-{candidate_component}",
                "stream": "B",
                "concern": "sink-without-source",
                "sink_id": sid,
                "sink_class": sink_class,
                "lib": lib,
                "parameterization": parameterization,
            }
        )

    # Pull every symbol whose name suggests it gates access. The original
    # set (``authoriz``/``authent``/``permission``) missed common naming
    # conventions like ``verifyAdminKey``, ``apiKey``, ``requireRole``,
    # ``hasAccess``, ``isOwner``, etc., so the wide nominator skipped real
    # auth callsites entirely on codebases that don't spell things out.
    auth_rows = conn.execute(
        """
        SELECT id, file, range_start, display_name
        FROM symbols
        WHERE display_name ILIKE '%authoriz%'
           OR display_name ILIKE '%authent%'
           OR display_name ILIKE '%permission%'
           OR display_name ILIKE '%verify%'
           OR display_name ILIKE '%require%role%'
           OR display_name ILIKE '%require%auth%'
           OR display_name ILIKE '%require%admin%'
           OR display_name ILIKE '%require%login%'
           OR display_name ILIKE '%api_key%'
           OR display_name ILIKE '%apikey%'
           OR display_name ILIKE '%admin_key%'
           OR display_name ILIKE '%adminkey%'
           OR display_name ILIKE '%has_access%'
           OR display_name ILIKE '%hasaccess%'
           OR display_name ILIKE '%has_role%'
           OR display_name ILIKE '%hasrole%'
           OR display_name ILIKE '%is_owner%'
           OR display_name ILIKE '%isowner%'
           OR display_name ILIKE '%is_admin%'
           OR display_name ILIKE '%isadmin%'
           OR display_name ILIKE '%check_role%'
           OR display_name ILIKE '%checkrole%'
           OR display_name ILIKE '%check_auth%'
           OR display_name ILIKE '%checkauth%'
           OR display_name ILIKE '%guard%'
        """
    ).fetchall()
    for sym_id, file, line, name in auth_rows:
        candidate_component = _candidate_id_component(sym_id)
        queue.append(
            {
                "id": f"B-auth-{candidate_component}",
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
    conn: duckdb.DuckDBPyConnection,
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
    bundles_dir = state.run_dir / "bundles"
    with queue_path.open("w", encoding="utf-8") as f:
        for q in queue:
            bundle = build_evidence_bundle(
                conn,
                q,
                source_root=repo_dir / "source",
            )
            bundle_json, bundle_md = write_evidence_bundle(bundle, bundles_dir=bundles_dir)
            enriched = {
                **q,
                "bundle_json": str(bundle_json),
                "bundle_md": str(bundle_md),
            }
            f.write(json.dumps(enriched) + "\n")


def _empty_nominations_md() -> str:
    return (
        "# Nominations\n\n"
        "## Stream A — Pre-traced (CodeQL flows ready for triage)\n\n"
        "## Stream B — AI-discovered candidates (no static flow exists; semantic concern)\n\n"
        "## Stream C — Proposed CodeQL model extensions\n"
    )


def _update_context_digest(digest: Any, path: Path, *, label: str) -> None:
    digest.update(label.encode("utf-8"))
    digest.update(b"\0")
    if path.is_file() and not path.is_symlink():
        digest.update(path.read_bytes())
    else:
        digest.update(b"missing")
    digest.update(b"\0")


def _nomination_context_fingerprint(
    state: RunState,
    *,
    repo_dir: Path,
    llm: LLMConfig,
) -> str:
    """Bind generated nominations to their model, source, queue, and prompt."""
    digest = hashlib.sha256()
    digest.update(
        build_llm_context_fingerprint(llm, source_root=repo_dir / "source").encode("utf-8")
    )
    digest.update(json.dumps(state.target_bug_classes, sort_keys=True).encode("utf-8"))
    for label, path in (
        ("prompt", SKILL_DIR / "prompts" / "nominator.md"),
        ("queue", state.run_dir / "queue.jsonl"),
        ("repo", state.run_dir / "inputs" / "repo.md"),
        ("entrypoints", state.run_dir / "inputs" / "entrypoints.md"),
    ):
        _update_context_digest(digest, path, label=label)
    return digest.hexdigest()


def _reset_nomination_attempt_if_needed(
    state: RunState,
    *,
    nominations_path: Path,
    context_fingerprint: str,
    reusable: bool,
) -> None:
    """Start a fresh generated document when any nomination input changed."""
    context_path = state.run_dir / ".nominate-context"
    previous = ""
    if context_path.is_file():
        previous = context_path.read_text(encoding="utf-8", errors="replace").strip()
    if reusable and previous == context_fingerprint:
        return
    done_dir = state.run_dir / ".done"
    if done_dir.is_dir():
        for marker in done_dir.iterdir():
            if marker.is_file() or marker.is_symlink():
                marker.unlink(missing_ok=True)
    nominations_path.write_text(_empty_nominations_md(), encoding="utf-8")
    context_path.write_text(context_fingerprint + "\n", encoding="utf-8")


def write_llm_cmd_script(target: Path, llm: LLMConfig) -> Path:
    """Write a one-shot wrapper script that invokes ``llm`` with stdin-piped prompt.

    The skill loop calls this script with the prompt on stdin. The script
    forwards the configured argv to the LLM CLI. Every CLI we support
    accepts the prompt as the final positional arg, so we read stdin into
    a shell variable and append it.
    """
    argv = build_argv(llm, "__PROMPT_PLACEHOLDER__")
    if argv[-1] != "__PROMPT_PLACEHOLDER__":
        raise RuntimeError("argv builder did not place prompt last")
    prefix = " ".join(shlex.quote(a) for a in argv[:-1])
    body = (
        "#!/usr/bin/env bash\n"
        "# Auto-generated by ai-codescan; edits will be lost on next run.\n"
        "set -euo pipefail\n"
        'PROMPT="$(cat -)"\n'
        f'exec {prefix} "$PROMPT"\n'
    )
    target.write_text(body, encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


def run_nominator(
    state: RunState,
    *,
    repo_dir: Path,
    bug_classes: list[BugClass],
    db_path: Path,
    llm: LLMConfig | None = None,
) -> Path:
    """Stage inputs, drive the skill loop, return path to nominations.md."""
    conn = duckdb.connect(str(db_path))
    try:
        queue = build_queue(
            conn,
            target_bug_classes=[c.name for c in bug_classes],
        )
        scores = score_candidates(conn, queue, source_root=repo_dir / "source")
        persist_candidate_scores(conn, scores)
        queue = attach_scores(queue, scores)
        _stage_inputs(state, repo_dir, queue, conn)
    finally:
        conn.close()
    state.phase = "nominate"
    save(state)

    nominations_path = state.run_dir / "nominations.md"

    effective = llm or LLMConfig(provider=state.llm_provider, model=state.llm_model)
    context_fingerprint = _nomination_context_fingerprint(
        state,
        repo_dir=repo_dir,
        llm=effective,
    )
    _reset_nomination_attempt_if_needed(
        state,
        nominations_path=nominations_path,
        context_fingerprint=context_fingerprint,
        reusable=bool(effective.model),
    )
    if not is_available(effective.provider):
        return nominations_path

    cmd_script = write_llm_cmd_script(state.run_dir / ".llm-cmd.sh", effective)

    env = os.environ.copy()
    env["AI_CODESCAN_RUN_DIR"] = str(state.run_dir)
    env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
    env["AI_CODESCAN_TARGET_BUG_CLASSES"] = ",".join(c.name for c in bug_classes)
    env["AI_CODESCAN_LLM_CMD"] = str(cmd_script)
    env["AI_CODESCAN_SOURCE_ROOT"] = str(repo_dir / "source")
    env["CLAUDE_NO_AUTO_REGISTER"] = "1"

    subprocess.run(  # noqa: S603 - argv-only, no shell; bash is on PATH
        ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
        env=env,
        check=True,
    )
    return nominations_path
