"""Layer 5: storage / second-order taint.

Resolves storage locations (SQL columns, cache keys, queue topics, env vars,
file paths) from source code, then runs a two-pass fixpoint:

  Round 0 — regular flows (Phase 1)
  Round 1 — for each WRITE sink, mark the storage location dirty with the
            contributing source TIDs.
  Round 2 — every READ from a dirty storage location becomes a fresh source
            carrying that location's accumulated TIDs.
  Repeat until storage_taint stabilises (cap at 5 iterations).

The persistent annotation lives at ``<cache>/schema.taint.yml`` (IDA ``.til``
analogue) and is hand-editable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb
import sqlglot
import yaml

_SQL_WRITE_VERBS = {"insert", "update"}
_SQL_READ_VERBS = {"select"}

_FIXPOINT_MAX_ROUNDS = 5

# Heuristic detection of storage operations by callee text.
_SQL_CALL = re.compile(
    r"\b(?:db|conn|client|pool|knex)\.(?:query|execute|run|raw)$",
    re.IGNORECASE,
)
_CACHE_SET = re.compile(r"\b(?:cache|redis|client)\.(?:set|hset|setex)$", re.IGNORECASE)
_CACHE_GET = re.compile(r"\b(?:cache|redis|client)\.(?:get|hget|mget)$", re.IGNORECASE)
_QUEUE_PUBLISH = re.compile(
    r"\b(?:queue|jobs|publisher|producer|kafka|amqp)\.(?:publish|emit|add|send)$",
    re.IGNORECASE,
)
_QUEUE_CONSUME = re.compile(
    r"\b(?:queue|worker|consumer|subscriber)\.(?:process|consume|subscribe|on)$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class StorageOp:
    storage_id: str
    kind: str  # 'sql_column' | 'cache_key' | 'queue_topic' | 'file_path' | 'env_var'
    op: str  # 'write' | 'read'
    confidence: str  # 'definite' | 'inferred' | 'llm-suggested'


def detect_sql_storage_ids(sql_text: str, *, dialect: str | None = None) -> list[str]:
    """Return ``sql:<table>.<column>`` identifiers referenced by ``sql_text``."""
    out: list[str] = []
    try:
        tree = sqlglot.parse_one(sql_text, read=dialect)
    except sqlglot.errors.ParseError:
        return []
    if tree is None:
        return []

    table_alias_map: dict[str, str] = {}
    for table in tree.find_all(sqlglot.exp.Table):
        if table.alias:
            table_alias_map[table.alias_or_name.lower()] = table.name.lower()

    # Identify the dominant table for unqualified columns (first FROM-clause table).
    main_table_name = ""
    first_table = tree.find(sqlglot.exp.Table)
    if first_table is not None:
        main_table_name = first_table.name.lower()

    for col in tree.find_all(sqlglot.exp.Column):
        column_name = col.name.lower()
        table_name = (col.table or "").lower()
        if table_name in table_alias_map:
            table_name = table_alias_map[table_name]
        if not table_name:
            table_name = main_table_name
        if not table_name or not column_name:
            continue
        out.append(f"sql:{table_name}.{column_name}")
    return sorted(set(out))


def classify_sql_op(sql_text: str) -> str | None:
    """Return ``'write'`` for INSERT/UPDATE, ``'read'`` for SELECT, else ``None``."""
    try:
        tree = sqlglot.parse_one(sql_text)
    except sqlglot.errors.ParseError:
        return None
    if tree is None:
        return None
    name = tree.key.lower() if tree.key else ""
    if name in _SQL_WRITE_VERBS:
        return "write"
    if name in _SQL_READ_VERBS:
        return "read"
    return None


def classify_call(callee_text: str) -> tuple[str, str] | None:
    """Classify a function-call callee by storage kind + op, or return None.

    Returns ``(kind, op)`` where ``kind`` is one of the ``storage_locations.kind``
    enum values and ``op`` is ``'write'``/``'read'``.
    """
    if _SQL_CALL.search(callee_text):
        # Op direction depends on the SQL string itself; deferred to caller.
        return ("sql_column", "unknown")
    if _CACHE_SET.search(callee_text):
        return ("cache_key", "write")
    if _CACHE_GET.search(callee_text):
        return ("cache_key", "read")
    if _QUEUE_PUBLISH.search(callee_text):
        return ("queue_topic", "write")
    if _QUEUE_CONSUME.search(callee_text):
        return ("queue_topic", "read")
    return None


def load_schema_yaml(path: Path) -> dict[str, Any]:
    """Load the persistent ``schema.taint.yml`` annotation file."""
    if not path.is_file():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def save_schema_yaml(path: Path, data: dict[str, Any]) -> None:
    """Persist the ``schema.taint.yml`` annotation file (sorted keys)."""
    path.write_text(yaml.safe_dump(data, sort_keys=True), encoding="utf-8")


@dataclass(frozen=True, slots=True)
class FixpointStats:
    rounds_run: int
    new_flows: int
    storage_locations: int


def run_fixpoint(conn: duckdb.DuckDBPyConnection) -> FixpointStats:
    """Compute storage taint to fixpoint over the existing ``flows`` table.

    Phase 2D minimal viable implementation:
      * Walks each flow's sink; if the sink's class is ``sql.exec``, parses its
        SARIF step text for SQL writes/reads and records the affected columns.
      * Marks every SQL column that ever received a tainted value as dirty.
      * Returns counts (no recursion in this MVP — round-1 only).

    Iteration to fixpoint (round 2+) requires re-running the static engine
    with synthesised sources at the dirty READ sites; deferred to the
    follow-up design pass for Phase 2D++.
    """
    flow_rows = conn.execute(
        """
        SELECT f.fid, f.tid, f.sid, f.steps_json
        FROM flows f
        JOIN taint_sinks s ON s.sid = f.sid
        WHERE s.class IN ('sql.exec', 'sql_column')
        """
    ).fetchall()

    storage_locations: dict[str, str] = {}  # storage_id -> kind
    storage_writes: list[tuple[str, str, str, str | None, str]] = []  # (sid, fid, tid, sym, shape)

    for fid, tid, sid, steps_json in flow_rows:
        steps: list[list] = json.loads(steps_json or "[]")
        sql_step_text = next(
            (
                str(s[0])
                for s in steps
                if len(s) >= 1 and isinstance(s[0], str) and " " in str(s[0])
            ),
            "",
        )
        # Heuristic: the step "code" string isn't always the SQL itself.
        # MVP just records the sink without SQL parsing when text isn't recognisable.
        if not sql_step_text:
            storage_locations.setdefault(f"sql:unknown.{sid[:8]}", "sql_column")
            storage_writes.append(
                (f"sql:unknown.{sid[:8]}", fid, tid, None, json.dumps({"shape": "unknown"}))
            )
            continue
        op = classify_sql_op(sql_step_text)
        ids = detect_sql_storage_ids(sql_step_text)
        for storage_id in ids:
            storage_locations[storage_id] = "sql_column"
            if op == "write":
                storage_writes.append(
                    (storage_id, fid, tid, None, json.dumps({"shape": "sql"}))
                )

    if storage_locations:
        conn.executemany(
            "INSERT OR REPLACE INTO storage_locations VALUES (?, ?, ?)",
            [(sid, kind, "fixpoint-mvp") for sid, kind in storage_locations.items()],
        )
    if storage_writes:
        conn.executemany(
            "INSERT INTO storage_writes VALUES (?, ?, ?, ?, ?)",
            storage_writes,
        )
        # Mark each location dirty with the union of contributing tids.
        rows: list[tuple[str, str, str, str]] = []
        for storage_id in storage_locations:
            tids = sorted(
                {
                    w[2]
                    for w in storage_writes
                    if w[0] == storage_id and w[2] is not None
                }
            )
            if tids:
                rows.append(
                    (
                        storage_id,
                        f"T-stored:{storage_id}",
                        json.dumps(tids),
                        "definite",
                    )
                )
        if rows:
            conn.executemany("INSERT INTO storage_taint VALUES (?, ?, ?, ?)", rows)

    return FixpointStats(
        rounds_run=1,
        new_flows=0,  # round 2 deferred — see docstring
        storage_locations=len(storage_locations),
    )
