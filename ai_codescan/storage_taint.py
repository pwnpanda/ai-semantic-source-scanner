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

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb
import sqlglot
import yaml

_SQL_WRITE_VERBS = {"insert", "update"}
_SQL_READ_VERBS = {"select"}

_FIXPOINT_MAX_ROUNDS = 5

# Heuristic detection of storage operations by callee text. Patterns cover
# JS/TS idioms (``db.query``, ``redis.set``), Python idioms (``cursor.execute``,
# ``r.set``, ``celery.send_task``), and Java idioms (``stmt.executeQuery``,
# ``jdbcTemplate.queryForList``); matched against the full callee string and
# anchored at the end so partial-name false matches don't bleed in.
# Two flavors: the broad cross-language SQL receiver+method match, and a
# narrow Go-specific match for ``sqlx.Get`` / ``sqlx.Select`` style calls
# whose method name (``Get``/``Select``) collides with cache reads on
# generic receivers like ``client.get``.
_SQL_CALL = re.compile(
    r"\b(?:db|conn|pool|knex|cursor|cur|session|engine|stmt|statement|"
    r"preparedStatement|jdbcTemplate|entityManager|em|tx)\."
    r"(?:query|execute|executemany|executeQuery|executeUpdate|"
    r"prepareStatement|createQuery|createNativeQuery|queryForList|"
    r"queryForObject|run|raw|"
    r"Exec|ExecContext|Query|QueryContext|QueryRow|QueryRowContext|"
    r"Prepare|PrepareContext|Raw)$"
    r"|\b(?:client|c)\."
    r"(?:query|execute|executemany|executeQuery|executeUpdate|run|raw|"
    r"Query|QueryContext|Exec|ExecContext|Prepare|PrepareContext|Raw)$"
    r"|\bsqlx\.(?:Get|Select|NamedExec|Exec|Query|QueryRow)$"
    # Ruby ActiveRecord and raw drivers.
    r"|\b(?:ActiveRecord::Base|connection|Mysql2::Client|PG::Connection|"
    r"SQLite3::Database)\."
    r"(?:where|find_by_sql|exec_query|execute|select_all|query)$"
    # PHP PDO / mysqli / WordPress wpdb / Laravel DB. Includes both
    # member-call (``$pdo->query``) and free-function (``mysqli_query``)
    # forms.
    r"|\$(?:pdo|db|mysqli|wpdb|conn|connection)->"
    r"(?:query|exec|execute|prepare|get_results|get_var|get_row|"
    r"executeQuery|executeStatement|raw|select|statement|whereRaw|selectRaw)$"
    r"|\bmysqli_(?:query|multi_query|real_query)$"
    # C# / .NET ADO.NET / Dapper / EF Core. ``cmd``/``command`` covers the
    # SqlCommand idiom; ``connection``/``conn`` covers Dapper extension
    # methods on ``IDbConnection``; ``Database`` covers EF Core's raw-SQL
    # methods.
    r"|\b(?:cmd|command|sqlCommand|conn|connection|db|Database|dbContext)\."
    r"(?:ExecuteNonQuery|ExecuteScalar|ExecuteReader|"
    r"ExecuteNonQueryAsync|ExecuteScalarAsync|ExecuteReaderAsync|"
    r"ExecuteSqlRaw|ExecuteSqlRawAsync|FromSqlRaw|SqlQueryRaw)$"
    # Kotlin Exposed ORM raw-SQL escape hatches. ``Transaction.exec`` /
    # ``Database.exec`` execute arbitrary SQL strings.
    r"|\b(?:transaction|tx|Transaction|TransactionManager|Database)\."
    r"(?:exec|execInBatch|execAndMap)$",
    re.IGNORECASE,
)
_CACHE_SET = re.compile(
    r"\b(?:cache|redis|client|r|kv|memcache|mc|redisTemplate|jedis|"
    r"valueOps|opsForValue|rdb)\."
    r"(?:set|hset|setex|mset|hmset|psetex|opsForValue|setIfAbsent|put|"
    r"Set|HSet|SetNX|SetEX|MSet|HMSet)$",
    re.IGNORECASE,
)
_CACHE_GET = re.compile(
    r"\b(?:cache|redis|client|r|kv|memcache|mc|redisTemplate|jedis|"
    r"valueOps|opsForValue|rdb)\."
    r"(?:get|hget|mget|hgetall|get_multi|getAndExpire|"
    r"Get|HGet|MGet|HGetAll)$",
    re.IGNORECASE,
)
_QUEUE_PUBLISH = re.compile(
    r"\b(?:queue|jobs|publisher|producer|kafka|amqp|celery|sqs|rabbit|"
    r"kafkaTemplate|jmsTemplate|rabbitTemplate)\."
    r"(?:publish|emit|add|send|send_task|apply_async|delay|send_message|"
    r"sendDefault|convertAndSend)$",
    re.IGNORECASE,
)
_QUEUE_CONSUME = re.compile(
    r"\b(?:queue|worker|consumer|subscriber|task|listener)\."
    r"(?:process|consume|subscribe|on|receive_messages|task|onMessage)$",
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
    except (sqlglot.errors.ParseError, sqlglot.errors.TokenError):
        # sqlglot raises TokenError (not ParseError) for malformed lexemes
        # like an unterminated quote. Treat both as "not SQL" — caller
        # asked us to be tolerant of arbitrary callee-text strings.
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
    except (sqlglot.errors.ParseError, sqlglot.errors.TokenError):
        # See ``detect_sql_storage_ids`` — sqlglot can raise TokenError on
        # malformed lexemes; treat as "not SQL".
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
                storage_writes.append((storage_id, fid, tid, None, json.dumps({"shape": "sql"})))

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
            tids = sorted({w[2] for w in storage_writes if w[0] == storage_id and w[2] is not None})
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


# ---------------------------------------------------------------------------
# Round 2: reads + dirty propagation + synthetic flows
# ---------------------------------------------------------------------------

# Walk JS/TS source files looking for SQL SELECT statements in template literals
# or quoted strings. Round-2 detection is intentionally textual (regex + sqlglot
# parse) rather than AST-based — it mirrors the round-1 SQL-string discovery
# already used upstream.
_JS_TS_GLOBS = (
    "**/*.js",
    "**/*.jsx",
    "**/*.ts",
    "**/*.tsx",
    "**/*.py",
    "**/*.java",
    "**/*.go",
    "**/*.rb",
    "**/*.rake",
    "**/*.php",
    "**/*.phtml",
    "**/*.cs",
    "**/*.cshtml",
    "**/*.kt",
    "**/*.kts",
)
_SELECT_STRING = re.compile(
    r"(?P<quote>['\"`])(?P<sql>\s*SELECT\b[^'\"`]*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)


def _stable_id(prefix: str, *parts: str) -> str:
    """Return ``<prefix><sha1[:12]>`` deterministic from ``parts``."""
    digest = hashlib.sha1("\x1f".join(parts).encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"{prefix}{digest[:12]}"


def _derived_tid_for_storage(storage_id: str) -> str:
    """Return the canonical round-2 derived ``tid`` for a storage location."""
    return _stable_id("T-stored-", storage_id)


def detect_storage_reads(conn: duckdb.DuckDBPyConnection, *, snapshot_root: Path) -> int:
    """Walk JS/TS source files and emit ``storage_reads`` rows for SELECT statements.

    For each ``SELECT <cols> FROM <table>`` literal found in the snapshot, emits
    one ``storage_reads(storage_id, symbol_id, result_binding_id)`` row per
    referenced ``sql:<table>.<column>`` storage_id, but only for storage_ids
    that already appear in ``storage_locations`` (i.e. discovered as writes by
    round 1) — round 2 only cares about reads of locations that *could* be
    dirty.

    ``symbol_id`` is synthesised as ``read:<relpath>:<line>`` so a future
    round can correlate reads to flow steps. ``result_binding_id`` is left
    NULL for now (binding tracking is out of scope for the round-2 MVP).

    Returns the number of rows inserted.
    """
    if not snapshot_root.is_dir():
        return 0

    known_locations = {
        row[0] for row in conn.execute("SELECT storage_id FROM storage_locations").fetchall()
    }
    existing_reads = {
        (row[0], row[1])
        for row in conn.execute("SELECT storage_id, symbol_id FROM storage_reads").fetchall()
    }

    new_rows: list[tuple[str, str, str | None]] = []
    for pattern in _JS_TS_GLOBS:
        for src_path in snapshot_root.glob(pattern):
            if not src_path.is_file():
                continue
            try:
                text = src_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for match in _SELECT_STRING.finditer(text):
                sql = match.group("sql").strip()
                if not sql:
                    continue
                if classify_sql_op(sql) != "read":
                    continue
                line = text.count("\n", 0, match.start()) + 1
                rel = src_path.relative_to(snapshot_root).as_posix()
                symbol_id = f"read:{rel}:{line}"
                for storage_id in detect_sql_storage_ids(sql):
                    if storage_id not in known_locations:
                        continue
                    key = (storage_id, symbol_id)
                    if key in existing_reads:
                        continue
                    existing_reads.add(key)
                    new_rows.append((storage_id, symbol_id, None))

    if new_rows:
        conn.executemany(
            "INSERT INTO storage_reads VALUES (?, ?, ?)",
            new_rows,
        )
    return len(new_rows)


def derive_storage_taint(conn: duckdb.DuckDBPyConnection) -> int:
    """Mark every storage_id reached by a flow dirty.

    For each ``storage_id`` in ``storage_writes`` that has at least one
    contributing flow with a non-null source ``tid``, insert a single
    ``storage_taint`` row keyed on a stable ``derived_tid`` of the form
    ``T-stored-<sha1(storage_id)[:12]>``.

    The function is idempotent: re-running it does not duplicate rows for
    already-derived storage_ids.

    Returns the number of new storage_taint rows inserted.
    """
    write_rows = conn.execute(
        "SELECT storage_id, source_tid FROM storage_writes WHERE source_tid IS NOT NULL"
    ).fetchall()
    if not write_rows:
        return 0

    contributing: dict[str, set[str]] = {}
    for storage_id, source_tid in write_rows:
        contributing.setdefault(storage_id, set()).add(source_tid)

    already_derived = {
        row[0]
        for row in conn.execute(
            "SELECT derived_tid FROM storage_taint WHERE derived_tid IS NOT NULL"
        ).fetchall()
    }

    new_rows: list[tuple[str, str, str, str]] = []
    for storage_id, tids in contributing.items():
        derived_tid = _derived_tid_for_storage(storage_id)
        if derived_tid in already_derived:
            continue
        new_rows.append(
            (
                storage_id,
                derived_tid,
                json.dumps(sorted(tids)),
                "definite",
            )
        )

    if new_rows:
        conn.executemany("INSERT INTO storage_taint VALUES (?, ?, ?, ?)", new_rows)
    return len(new_rows)


def _ensure_taint_source(
    conn: duckdb.DuckDBPyConnection,
    *,
    tid: str,
    class_: str,
    key: str,
    evidence_loc: str,
) -> None:
    """Insert a synthetic ``taint_sources`` row if not already present."""
    existing = conn.execute("SELECT 1 FROM taint_sources WHERE tid = ?", [tid]).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO taint_sources VALUES (?, ?, ?, ?, ?)",
            [tid, None, class_, key, evidence_loc],
        )


def _ensure_taint_sink(
    conn: duckdb.DuckDBPyConnection,
    *,
    sid: str,
    class_: str,
    lib: str,
    parameterization: str,
) -> None:
    """Insert a synthetic ``taint_sinks`` row if not already present."""
    existing = conn.execute("SELECT 1 FROM taint_sinks WHERE sid = ?", [sid]).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO taint_sinks VALUES (?, ?, ?, ?, ?, ?)",
            [sid, None, class_, lib, parameterization, "[]"],
        )


def _pick_dominant_cwe(conn: duckdb.DuckDBPyConnection, contributing_tids: list[str]) -> str:
    """Return the most common CWE across flows whose tid is in ``contributing_tids``."""
    if not contributing_tids:
        return ""
    placeholders = ", ".join(["?"] * len(contributing_tids))
    rows = conn.execute(
        f"SELECT cwe FROM flows WHERE tid IN ({placeholders}) AND cwe IS NOT NULL",  # noqa: S608 - placeholders are static '?' tokens, values bound separately
        contributing_tids,
    ).fetchall()
    if not rows:
        return ""
    counts = Counter(r[0] for r in rows if r[0])
    if not counts:
        return ""
    return counts.most_common(1)[0][0]


def _origin_step(conn: duckdb.DuckDBPyConnection, contributing_tids: list[str]) -> str:
    """Return a representative source location for the contributing tids."""
    if not contributing_tids:
        return ""
    row = conn.execute(
        "SELECT evidence_loc FROM taint_sources WHERE tid = ? AND evidence_loc IS NOT NULL",
        [contributing_tids[0]],
    ).fetchone()
    return row[0] if row and row[0] else ""


def _write_step(conn: duckdb.DuckDBPyConnection, storage_id: str) -> str:
    """Return a representative write-site step for ``storage_id``."""
    row = conn.execute(
        """
        SELECT f.steps_json FROM storage_writes w
        JOIN flows f ON f.fid = w.flow_id
        WHERE w.storage_id = ?
        LIMIT 1
        """,
        [storage_id],
    ).fetchone()
    if row and row[0]:
        try:
            steps = json.loads(row[0])
        except json.JSONDecodeError:
            return f"write:{storage_id}"
        if steps:
            first = steps[-1]
            if isinstance(first, list) and first:
                return str(first[0])
    return f"write:{storage_id}"


def synthesize_round2_flows(conn: duckdb.DuckDBPyConnection) -> int:
    """Emit synthetic round-2 ``flows`` rows linking dirty storage to read sites.

    For every dirty ``storage_id`` (i.e. one with a ``storage_taint`` row) and
    every recorded read of that location, emits exactly one synthetic flow:

    * ``fid`` — stable id of the form ``f-r2-<sha1(...)>``
    * ``tid`` — the storage's ``derived_tid``
    * ``sid`` — synthetic sink keyed on the read symbol
    * ``cwe`` — most common CWE among contributing flows (or empty)
    * ``engine`` — ``'storage-taint-r2'``
    * ``confidence`` — ``'inferred'``
    * ``steps_json`` — ``[origin, write_site, read_site]``

    Idempotent: existing synthetic flows (same ``fid``) are not re-inserted.
    Returns the number of new flow rows inserted.
    """
    dirty = conn.execute(
        "SELECT storage_id, derived_tid, contributing_tids_json FROM storage_taint"
    ).fetchall()
    if not dirty:
        return 0

    existing_fids = {row[0] for row in conn.execute("SELECT fid FROM flows").fetchall()}
    inserted = 0

    for storage_id, derived_tid, contributing_json in dirty:
        try:
            contributing = list(json.loads(contributing_json or "[]"))
        except json.JSONDecodeError:
            contributing = []
        cwe = _pick_dominant_cwe(conn, contributing)
        origin = _origin_step(conn, contributing)
        write_site = _write_step(conn, storage_id)

        _ensure_taint_source(
            conn,
            tid=derived_tid,
            class_="storage.read",
            key=storage_id,
            evidence_loc=storage_id,
        )

        reads = conn.execute(
            "SELECT symbol_id FROM storage_reads WHERE storage_id = ?",
            [storage_id],
        ).fetchall()
        for (read_symbol,) in reads:
            sid = _stable_id("S-r2-", storage_id, str(read_symbol))
            _ensure_taint_sink(
                conn,
                sid=sid,
                class_="storage.read",
                lib="storage-taint-r2",
                parameterization=str(read_symbol),
            )
            fid = _stable_id("f-r2-", derived_tid, sid)
            if fid in existing_fids:
                continue
            existing_fids.add(fid)
            steps = json.dumps(
                [
                    [origin or storage_id, 0, 0],
                    [write_site, 0, 0],
                    [str(read_symbol), 0, 0],
                ]
            )
            conn.execute(
                "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [fid, derived_tid, sid, cwe, "storage-taint-r2", steps, None, "inferred"],
            )
            inserted += 1
    return inserted


def run_full_fixpoint(
    conn: duckdb.DuckDBPyConnection,
    *,
    snapshot_root: Path,
    max_rounds: int = 3,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """Run the full Layer-5 fixpoint: round 1 + round 2 to convergence.

    Pipeline per iteration:
      1. ``run_fixpoint`` — discover SQL writes from existing flows.
      2. ``detect_storage_reads`` — find SELECT reads of known locations.
      3. ``derive_storage_taint`` — mark reached locations dirty.
      4. ``synthesize_round2_flows`` — emit storage→read synthetic flows.

    Optional pre-pass (round 0): when ``schema_path`` points at a
    ``schema.taint.yml`` containing an ``llm_suggested:`` block, those
    storage_ids are seeded into ``storage_locations`` + ``storage_taint`` and
    matching cache/queue read sites are detected so subsequent rounds can
    emit storage→read flows for them.

    Iterates until no new synthetic flows or storage writes are produced, or
    ``max_rounds`` is reached. Returns a dict with per-round counters.
    """
    rounds: list[dict[str, int]] = []
    total_new_flows = 0
    total_locations = 0
    total_reads = 0
    total_derived = 0

    seed_locs, seed_reads = (0, 0)
    if schema_path is not None:
        seed_locs, seed_reads = _seed_llm_suggested_locations(
            conn, schema_path=schema_path, snapshot_root=snapshot_root
        )
        total_locations += seed_locs
        total_reads += seed_reads

    for round_idx in range(1, max_rounds + 1):
        prior_writes = conn.execute("SELECT COUNT(*) FROM storage_writes").fetchone()
        prior_writes_n = prior_writes[0] if prior_writes else 0

        round1 = run_fixpoint(conn)
        reads_added = detect_storage_reads(conn, snapshot_root=snapshot_root)
        derived_added = derive_storage_taint(conn)
        flows_added = synthesize_round2_flows(conn)

        post_writes = conn.execute("SELECT COUNT(*) FROM storage_writes").fetchone()
        post_writes_n = post_writes[0] if post_writes else 0
        new_writes = post_writes_n - prior_writes_n

        total_new_flows += flows_added
        total_locations = max(total_locations, round1.storage_locations)
        total_reads += reads_added
        total_derived += derived_added
        rounds.append(
            {
                "round": round_idx,
                "locations": round1.storage_locations,
                "reads": reads_added,
                "derived": derived_added,
                "new_flows": flows_added,
                "new_writes": new_writes,
            }
        )

        # Convergence: nothing new at any layer of this iteration.
        if flows_added == 0 and new_writes == 0 and reads_added == 0 and derived_added == 0:
            break

    return {
        "rounds_run": len(rounds),
        "rounds": rounds,
        "new_flows": total_new_flows,
        "storage_locations": total_locations,
        "storage_reads": total_reads,
        "storage_taint_derived": total_derived,
        "llm_seeded_locations": seed_locs,
        "llm_seeded_reads": seed_reads,
    }


# ---------------------------------------------------------------------------
# LLM-suggested seeding (round 0): consume schema.taint.yml `llm_suggested:`
# ---------------------------------------------------------------------------


_DYNAMIC_READ_CALL = re.compile(
    r"\b(?:cache|redis|client|r|kv|memcache|mc)\.(?:get|hget|mget|hgetall|get_multi)\s*\(",
    re.IGNORECASE,
)
_DYNAMIC_WRITE_CALL = re.compile(
    r"\b(?:cache|redis|client|r|kv|memcache|mc)\.(?:set|hset|setex|mset|hmset|psetex)\s*\(",
    re.IGNORECASE,
)
_QUEUE_CONSUME_CALL = re.compile(
    r"\b(?:queue|worker|consumer|subscriber|task)\."
    r"(?:process|consume|subscribe|on|receive_messages|task)\s*\(",
    re.IGNORECASE,
)


def _key_pattern_to_regex(storage_id: str) -> re.Pattern[str]:
    """Convert a structural key like ``cache:user:*:profile`` into a regex
    matching the literal portions in source-code template strings.

    The regex deliberately matches the colon-joined tail of the key with
    ``*`` placeholders relaxed to any non-quote run, so a concrete call
    site like ``cache.get(`user:${id}:profile`)`` is recognised regardless
    of which JS interpolation form was used.
    """
    _, _, tail = storage_id.partition(":")
    if not tail:
        tail = storage_id
    parts = tail.split("*")
    escaped = r"[^`'\"\s]*".join(re.escape(p) for p in parts)
    return re.compile(escaped, re.IGNORECASE)


def _seed_llm_suggested_locations(
    conn: duckdb.DuckDBPyConnection,
    *,
    schema_path: Path,
    snapshot_root: Path,
) -> tuple[int, int]:
    """Load ``llm_suggested:`` from ``schema_path`` and seed it into the DB.

    Inserts one ``storage_locations`` + one ``storage_taint`` row per
    suggested storage_id, then scans the snapshot for cache/queue read
    sites whose key template matches the structural pattern and records
    them in ``storage_reads`` so the round-2 synthesizer can stitch a
    storage→read flow.

    Returns ``(locations_seeded, reads_seeded)``.
    """
    if not schema_path.is_file():
        return (0, 0)
    data = load_schema_yaml(schema_path)
    raw_suggested = data.get("llm_suggested") or {}
    if not isinstance(raw_suggested, dict) or not raw_suggested:
        return (0, 0)

    existing_locs = {
        row[0] for row in conn.execute("SELECT storage_id FROM storage_locations").fetchall()
    }
    existing_taint = {
        row[0]
        for row in conn.execute(
            "SELECT derived_tid FROM storage_taint WHERE derived_tid IS NOT NULL"
        ).fetchall()
    }

    locs_added = 0
    suggested: dict[str, dict[str, Any]] = {}
    for storage_id, meta in raw_suggested.items():
        if not isinstance(storage_id, str):
            continue
        meta_dict = meta if isinstance(meta, dict) else {}
        suggested[storage_id] = meta_dict
        kind = str(meta_dict.get("kind", "unknown"))
        if storage_id not in existing_locs:
            conn.execute(
                "INSERT OR REPLACE INTO storage_locations VALUES (?, ?, ?)",
                [storage_id, kind, "llm_suggested"],
            )
            existing_locs.add(storage_id)
            locs_added += 1
        derived_tid = _derived_tid_for_storage(storage_id)
        if derived_tid not in existing_taint:
            conn.execute(
                "INSERT INTO storage_taint VALUES (?, ?, ?, ?)",
                [storage_id, derived_tid, json.dumps([]), "llm-suggested"],
            )
            existing_taint.add(derived_tid)
        _ensure_taint_source(
            conn,
            tid=derived_tid,
            class_="storage.read",
            key=storage_id,
            evidence_loc=storage_id,
        )

    reads_added = _detect_dynamic_storage_reads(
        conn, snapshot_root=snapshot_root, suggested=suggested
    )
    return (locs_added, reads_added)


def _detect_dynamic_storage_reads(
    conn: duckdb.DuckDBPyConnection,
    *,
    snapshot_root: Path,
    suggested: dict[str, dict[str, Any]],
) -> int:
    """Scan source for cache/queue read sites matching LLM-suggested keys."""
    if not snapshot_root.is_dir() or not suggested:
        return 0

    cache_ids = [sid for sid, meta in suggested.items() if meta.get("kind") == "cache_key"]
    queue_ids = [sid for sid, meta in suggested.items() if meta.get("kind") == "queue_topic"]
    if not cache_ids and not queue_ids:
        return 0

    cache_patterns = {sid: _key_pattern_to_regex(sid) for sid in cache_ids}
    queue_patterns = {sid: _key_pattern_to_regex(sid) for sid in queue_ids}

    existing_reads = {
        (row[0], row[1])
        for row in conn.execute("SELECT storage_id, symbol_id FROM storage_reads").fetchall()
    }

    new_rows: list[tuple[str, str, str | None]] = []
    for glob_pattern in _JS_TS_GLOBS:
        for src_path in snapshot_root.glob(glob_pattern):
            if not src_path.is_file():
                continue
            try:
                text = src_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = src_path.relative_to(snapshot_root).as_posix()
            _scan_dynamic_calls(
                text=text,
                rel=rel,
                call_regex=_DYNAMIC_READ_CALL,
                key_patterns=cache_patterns,
                existing=existing_reads,
                out=new_rows,
            )
            _scan_dynamic_calls(
                text=text,
                rel=rel,
                call_regex=_QUEUE_CONSUME_CALL,
                key_patterns=queue_patterns,
                existing=existing_reads,
                out=new_rows,
            )

    if new_rows:
        conn.executemany(
            "INSERT INTO storage_reads VALUES (?, ?, ?)",
            new_rows,
        )
    return len(new_rows)


def _scan_dynamic_calls(  # noqa: PLR0913 - keyword-only fan-in is the cleanest expression here
    *,
    text: str,
    rel: str,
    call_regex: re.Pattern[str],
    key_patterns: dict[str, re.Pattern[str]],
    existing: set[tuple[str, str]],
    out: list[tuple[str, str, str | None]],
) -> None:
    """Append ``storage_reads`` rows where a call's argument matches a key."""
    for match in call_regex.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        tail = text[match.end() : match.end() + 200]
        symbol_id = f"read:{rel}:{line}"
        for storage_id, regex in key_patterns.items():
            if not regex.search(tail):
                continue
            key = (storage_id, symbol_id)
            if key in existing:
                continue
            existing.add(key)
            out.append((storage_id, symbol_id, None))


# ---------------------------------------------------------------------------
# LLM-driven storage-id resolution (round 3)
# ---------------------------------------------------------------------------


# Dynamic-key tells: JS template ``${...}`` interpolation, ``+ name`` concat,
# opening backtick + ``$``, OR Python ``f"...{x}..."`` / ``"..." % x`` /
# ``"...".format(x)`` patterns.
_DYNAMIC_TEMPLATE = re.compile(
    r"\$\{[^}]+\}"  # JS ${...}
    r"|\+\s*[A-Za-z_]\w*"  # JS string + ident
    r"|`[^`]*\$"  # JS backtick template
    r"|\bf[\"'][^\"']*\{[^}]+\}"  # Python f"...{x}..."
    r"|[\"'][^\"']*[\"']\s*%\s*"  # Python "%s" %
    r"|\.format\("  # Python .format(...)
)

# Line-scoped variants of the original callee regexes (no end-of-string anchor)
# for searching whole snippets rather than isolated callee strings.
_CACHE_SET_LINE = re.compile(
    r"\b(?:cache|redis|client|r|kv|memcache|mc)\.(?:set|hset|setex|mset|hmset|psetex)\b",
    re.IGNORECASE,
)
_CACHE_GET_LINE = re.compile(
    r"\b(?:cache|redis|client|r|kv|memcache|mc)\.(?:get|hget|mget|hgetall|get_multi)\b",
    re.IGNORECASE,
)
_QUEUE_PUBLISH_LINE = re.compile(
    r"\b(?:queue|jobs|publisher|producer|kafka|amqp|celery|sqs|rabbit)\."
    r"(?:publish|emit|add|send|send_task|apply_async|delay|send_message)\b",
    re.IGNORECASE,
)
_QUEUE_CONSUME_LINE = re.compile(
    r"\b(?:queue|worker|consumer|subscriber|task)\."
    r"(?:process|consume|subscribe|on|receive_messages|task)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class UnresolvedCall:
    """A storage call site the static detector couldn't pin to a key."""

    call_id: str
    file: str
    line: int
    callee: str
    code_snippet: str
    context_lines: list[str]


def find_unresolved_dynamic_calls(
    conn: duckdb.DuckDBPyConnection,
    *,
    snapshot_root: Path,
    context_radius: int = 3,
) -> list[UnresolvedCall]:
    """Find cache/queue/file calls that have a dynamic key the static analyser
    couldn't resolve. Used as input to the storage-taint-resolver skill.

    Heuristic: any callsite whose ``calleeText`` matches a storage operation
    AND whose code contains a template-literal hole (``${...}``), an
    addition operator on identifiers, or a function-call receiver.
    """
    out: list[UnresolvedCall] = []
    rows = conn.execute(
        """
        SELECT caller_id, file, line, kind FROM xrefs
        WHERE kind = 'call' AND file IS NOT NULL AND line IS NOT NULL
        """
    ).fetchall()
    for caller_id, file, line, _kind in rows:
        # Read the line + surrounding context from the snapshot.
        try:
            text = Path(file).read_text(encoding="utf-8")
        except OSError:
            continue
        lines = text.splitlines()
        idx = int(line) - 1
        if idx < 0 or idx >= len(lines):
            continue
        snippet = lines[idx]

        # Filter to storage callees of interest, then keep only dynamic ones.
        callee_match = (
            _CACHE_SET_LINE.search(snippet)
            or _CACHE_GET_LINE.search(snippet)
            or _QUEUE_PUBLISH_LINE.search(snippet)
            or _QUEUE_CONSUME_LINE.search(snippet)
        )
        if not callee_match:
            continue
        if not _DYNAMIC_TEMPLATE.search(snippet):
            continue

        context_start = max(0, idx - context_radius)
        context_end = min(len(lines), idx + context_radius + 1)
        context = lines[context_start:context_end]

        call_id = f"S-{_stable_id('dyn', file, str(line), snippet)[:12]}"
        out.append(
            UnresolvedCall(
                call_id=call_id,
                file=file,
                line=int(line),
                callee=callee_match.group(0),
                code_snippet=snippet.strip(),
                context_lines=[ln for ln in context],
            )
        )
        _ = caller_id  # reserved
    _ = snapshot_root  # reserved for future per-snapshot resolution
    # Deduplicate by call_id (same line might be picked by multiple regexes).
    by_id = {c.call_id: c for c in out}
    return list(by_id.values())


def write_resolver_queue(run_dir: Path, calls: list[UnresolvedCall]) -> Path:
    """Stage the resolver queue under ``<run_dir>/storage_resolver/queue.jsonl``."""
    queue_dir = run_dir / "storage_resolver"
    queue_dir.mkdir(parents=True, exist_ok=True)
    queue_path = queue_dir / "queue.jsonl"
    with queue_path.open("w", encoding="utf-8") as f:
        for c in calls:
            f.write(
                json.dumps(
                    {
                        "call_id": c.call_id,
                        "file": c.file,
                        "line": c.line,
                        "callee": c.callee,
                        "code_snippet": c.code_snippet,
                        "context_lines": c.context_lines,
                    }
                )
            )
            f.write("\n")
    return queue_path


def parse_resolver_proposals(run_dir: Path) -> list[dict[str, Any]]:
    """Parse ``proposals.jsonl`` written by the storage-taint-resolver skill."""
    p = run_dir / "storage_resolver" / "proposals.jsonl"
    if not p.is_file():
        return []
    out: list[dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            out.append(data)
    return out


def merge_proposals_into_schema(
    schema_path: Path,
    proposals: list[dict[str, Any]],
    *,
    min_confidence: float = 0.4,
) -> int:
    """Merge LLM-suggested storage IDs into ``schema.taint.yml``.

    Each accepted proposal lands under a top-level ``llm_suggested:`` block
    keyed by ``storage_id`` so a human reviewer can audit / promote them
    later. Returns the count of proposals merged.
    """
    if not proposals:
        return 0
    data = load_schema_yaml(schema_path)
    suggested: dict[str, Any] = data.setdefault("llm_suggested", {})
    merged = 0
    for prop in proposals:
        sid = prop.get("storage_id")
        if not sid or not isinstance(sid, str):
            continue
        confidence = float(prop.get("confidence", 0.0) or 0.0)
        if confidence < min_confidence:
            continue
        if sid in suggested:
            continue  # don't overwrite human-reviewed entries
        suggested[sid] = {
            "kind": str(prop.get("kind", "unknown")),
            "confidence": confidence,
            "rationale": str(prop.get("rationale", "")),
            "call_id": str(prop.get("call_id", "")),
        }
        merged += 1
    save_schema_yaml(schema_path, data)
    return merged
