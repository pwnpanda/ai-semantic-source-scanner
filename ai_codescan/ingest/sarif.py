"""Parse SARIF and ingest taint sources, sinks, and flows into DuckDB."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb

_CWE_RE = re.compile(r"cwe[-/](\d+)", re.IGNORECASE)


def _extract_cwe(rule_id: str, tags: list[str]) -> str | None:
    for token in [rule_id, *tags]:
        m = _CWE_RE.search(token or "")
        if m:
            return f"CWE-{int(m.group(1))}"
    return None


def _stable_id(prefix: str, *parts: str) -> str:
    blob = "|".join(parts)
    digest = hashlib.sha1(blob.encode("utf-8"), usedforsecurity=False).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _physical_to_loc(phys: dict[str, Any], snapshot_root: Path) -> tuple[str, int, int]:
    uri = phys.get("artifactLocation", {}).get("uri", "")
    region = phys.get("region", {})
    file_abs = (snapshot_root / uri).as_posix() if uri else ""
    start = int(region.get("startLine", 0))
    end = int(region.get("endLine", region.get("startLine", 0)))
    return file_abs, start, end


@dataclass(frozen=True)
class _IngestCtx:
    """Bundle of contextual parameters that apply to every SARIF result."""

    project_id: str
    snapshot_root: Path
    engine: str
    sarif_path: Path
    rule_tags: dict[str, list[str]]
    """``rule_id`` → tags collected from ``tool.driver.rules[*].properties.tags``.
    Semgrep stores rule-level metadata (e.g. CWE-208) on the rule definition
    rather than on each result, so per-result ``properties.tags`` is often
    empty even when the rule clearly carries a CWE label. Looking the rule up
    here lets ``_extract_cwe`` find it."""


def _ingest_result(conn: duckdb.DuckDBPyConnection, result: dict[str, Any], ctx: _IngestCtx) -> int:
    tags = (result.get("properties", {}) or {}).get("tags", []) or []
    rule_id = result.get("ruleId", "")
    if not tags:
        tags = ctx.rule_tags.get(rule_id, [])
    cwe = _extract_cwe(rule_id, tags)
    sink_loc = result.get("locations", [{}])[0].get("physicalLocation", {})
    sink_file, sink_start, _sink_end = _physical_to_loc(sink_loc, ctx.snapshot_root)
    sid = _stable_id("sink", ctx.project_id, sink_file, str(sink_start), rule_id)
    conn.execute(
        "INSERT OR REPLACE INTO taint_sinks VALUES (?, ?, ?, ?, ?, ?)",
        [sid, None, rule_id, None, "unknown", "[]"],
    )

    flows_inserted = 0
    for flow in result.get("codeFlows", []):
        for thread in flow.get("threadFlows", []):
            locs = thread.get("locations", [])
            if not locs:
                continue
            src_phys = locs[0].get("location", {}).get("physicalLocation", {})
            src_file, src_start, _src_end = _physical_to_loc(src_phys, ctx.snapshot_root)
            tid = _stable_id("source", ctx.project_id, src_file, str(src_start), rule_id)
            src_msg = locs[0].get("location", {}).get("message", {}).get("text")
            conn.execute(
                "INSERT OR REPLACE INTO taint_sources VALUES (?, ?, ?, ?, ?)",
                [tid, None, "unknown", src_msg, f"{src_file}:{src_start}"],
            )
            fid = _stable_id("flow", ctx.project_id, tid, sid)
            steps_json = json.dumps(
                [
                    _physical_to_loc(
                        step.get("location", {}).get("physicalLocation", {}),
                        ctx.snapshot_root,
                    )
                    for step in locs
                ]
            )
            conn.execute(
                "INSERT OR REPLACE INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [fid, tid, sid, cwe, ctx.engine, steps_json, str(ctx.sarif_path), "definite"],
            )
            flows_inserted += 1

    # Pattern-only / non-taint rules (e.g. Semgrep's plain ``patterns`` mode,
    # CodeQL ``problem`` queries) emit results with a single ``locations``
    # entry and no ``codeFlows`` array. Treat the primary location as both
    # source and sink so the finding still lands in the ``flows`` table; the
    # downstream nominator sees one-step paths exactly the same as multi-step
    # ones.
    if flows_inserted == 0 and sink_file:
        tid = _stable_id("source", ctx.project_id, sink_file, str(sink_start), rule_id)
        msg = result.get("message", {}).get("text", "")
        conn.execute(
            "INSERT OR REPLACE INTO taint_sources VALUES (?, ?, ?, ?, ?)",
            [tid, None, "pattern", msg, f"{sink_file}:{sink_start}"],
        )
        fid = _stable_id("flow", ctx.project_id, tid, sid)
        steps_json = json.dumps([[sink_file, sink_start, sink_start]])
        conn.execute(
            "INSERT OR REPLACE INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [fid, tid, sid, cwe, ctx.engine, steps_json, str(ctx.sarif_path), "definite"],
        )
        flows_inserted = 1
    return flows_inserted


def ingest_sarif(
    conn: duckdb.DuckDBPyConnection,
    *,
    sarif_path: Path,
    project_id: str,
    snapshot_root: Path,
    engine: str,
) -> int:
    """Ingest one SARIF file. Returns the number of flows ingested.

    Idempotent: re-ingesting the same SARIF leaves the DB unchanged.
    """
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    flows_inserted = 0
    for run in data.get("runs", []):
        rule_tags: dict[str, list[str]] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            rid = rule.get("id", "")
            if not rid:
                continue
            tags = (rule.get("properties", {}) or {}).get("tags", []) or []
            rule_tags[rid] = list(tags)
        ctx = _IngestCtx(
            project_id=project_id,
            snapshot_root=snapshot_root,
            engine=engine,
            sarif_path=sarif_path,
            rule_tags=rule_tags,
        )
        for result in run.get("results", []):
            flows_inserted += _ingest_result(conn, result, ctx)
    return flows_inserted
