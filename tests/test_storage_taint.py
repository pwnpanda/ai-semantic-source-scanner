"""Tests for ai_codescan.storage_taint."""

from pathlib import Path

import duckdb
import yaml

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.storage_taint import (
    classify_call,
    classify_sql_op,
    derive_storage_taint,
    detect_sql_storage_ids,
    detect_storage_reads,
    find_unresolved_dynamic_calls,
    load_schema_yaml,
    merge_proposals_into_schema,
    parse_resolver_proposals,
    run_fixpoint,
    run_full_fixpoint,
    save_schema_yaml,
    synthesize_round2_flows,
)


def test_detect_sql_storage_ids_simple_select() -> None:
    ids = detect_sql_storage_ids("SELECT id, name FROM users WHERE id = 5")
    assert "sql:users.id" in ids
    assert "sql:users.name" in ids


def test_detect_sql_storage_ids_with_alias() -> None:
    ids = detect_sql_storage_ids("SELECT u.bio FROM users u WHERE u.id = 1")
    assert "sql:users.bio" in ids


def test_classify_sql_op_select() -> None:
    assert classify_sql_op("SELECT * FROM users") == "read"


def test_classify_sql_op_update() -> None:
    assert classify_sql_op("UPDATE users SET bio = 'x' WHERE id = 1") == "write"


def test_classify_sql_op_unknown() -> None:
    assert classify_sql_op("VACUUM users") is None


def test_classify_call_recognises_redis_get() -> None:
    assert classify_call("client.get") == ("cache_key", "read")


def test_classify_call_recognises_queue_publish() -> None:
    assert classify_call("queue.publish") == ("queue_topic", "write")


def test_classify_call_returns_none_for_random() -> None:
    assert classify_call("Math.random") is None


def test_classify_call_recognises_python_cursor_execute() -> None:
    assert classify_call("cursor.execute") == ("sql_column", "unknown")
    assert classify_call("cur.executemany") == ("sql_column", "unknown")


def test_classify_call_recognises_python_redis_set() -> None:
    assert classify_call("r.set") == ("cache_key", "write")
    assert classify_call("r.hgetall") == ("cache_key", "read")


def test_classify_call_recognises_celery_send_task() -> None:
    assert classify_call("celery.send_task") == ("queue_topic", "write")
    assert classify_call("celery.apply_async") == ("queue_topic", "write")


def test_classify_call_recognises_java_jdbc() -> None:
    assert classify_call("stmt.executeQuery") == ("sql_column", "unknown")
    assert classify_call("preparedStatement.executeUpdate") == ("sql_column", "unknown")
    assert classify_call("jdbcTemplate.queryForList") == ("sql_column", "unknown")


def test_classify_call_recognises_spring_redis() -> None:
    assert classify_call("redisTemplate.opsForValue") == ("cache_key", "write")


def test_classify_call_recognises_spring_kafka_template() -> None:
    assert classify_call("kafkaTemplate.convertAndSend") == ("queue_topic", "write")


def test_classify_call_recognises_go_database_sql() -> None:
    assert classify_call("db.Query") == ("sql_column", "unknown")
    assert classify_call("db.QueryContext") == ("sql_column", "unknown")
    assert classify_call("tx.Exec") == ("sql_column", "unknown")


def test_classify_call_recognises_go_redis_set() -> None:
    assert classify_call("rdb.Set") == ("cache_key", "write")
    assert classify_call("rdb.Get") == ("cache_key", "read")


def test_load_save_schema_yaml_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "schema.taint.yml"
    data = {"tables": {"users": {"columns": {"bio": {"taint": "dirty"}}}}}
    save_schema_yaml(target, data)
    assert load_schema_yaml(target) == data


def test_load_schema_yaml_missing_returns_empty(tmp_path: Path) -> None:
    assert load_schema_yaml(tmp_path / "missing.yml") == {}


def test_run_fixpoint_records_storage_locations(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute("INSERT INTO taint_sources VALUES ('T1', NULL, 'http.body', 'name', 'a:1')")
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F1', 'T1', 'K1', 'CWE-89', 'codeql', '[[\"UPDATE users SET bio = 1\", 1, 1]]', "
        "'/sarif', 'definite')"
    )
    stats = run_fixpoint(conn)
    assert stats.rounds_run == 1
    locs = conn.execute("SELECT storage_id FROM storage_locations").fetchall()
    assert ("sql:users.bio",) in locs or ("sql:users.id",) in locs or len(locs) >= 1


# ---------------------------------------------------------------------------
# Round-2 tests
# ---------------------------------------------------------------------------


def _seed_round1_users_bio(conn: duckdb.DuckDBPyConnection) -> None:
    """Seed schema + a flow that updates users.bio so storage_writes has content."""
    apply_schema(conn)
    conn.execute("INSERT INTO taint_sources VALUES ('T1', NULL, 'http.body', 'name', 'a:1')")
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F1', 'T1', 'K1', 'CWE-89', 'codeql', "
        "'[[\"UPDATE users SET bio = 1\", 1, 1]]', '/sarif', 'definite')"
    )
    run_fixpoint(conn)


def test_detect_storage_reads_from_select_statements(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    _seed_round1_users_bio(conn)

    snapshot_root = tmp_path / "source"
    snapshot_root.mkdir()
    js_file = snapshot_root / "reader.js"
    js_file.write_text(
        "const rows = await db.query('SELECT bio FROM users WHERE id = 1');\n",
        encoding="utf-8",
    )

    inserted = detect_storage_reads(conn, snapshot_root=snapshot_root)
    assert inserted >= 1
    rows = conn.execute("SELECT storage_id, symbol_id FROM storage_reads").fetchall()
    assert any(storage_id == "sql:users.bio" for storage_id, _ in rows)
    # Re-running is idempotent.
    second = detect_storage_reads(conn, snapshot_root=snapshot_root)
    assert second == 0


def test_derive_storage_taint_marks_locations_with_flows_dirty(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    _seed_round1_users_bio(conn)
    # Wipe round-1's storage_taint rows so derive_storage_taint is observable.
    conn.execute("DELETE FROM storage_taint")

    derived = derive_storage_taint(conn)
    assert derived >= 1
    rows = conn.execute(
        "SELECT storage_id, derived_tid, contributing_tids_json, confidence FROM storage_taint"
    ).fetchall()
    assert rows
    storage_id, derived_tid, contrib_json, confidence = rows[0]
    assert storage_id == "sql:users.bio"
    assert derived_tid.startswith("T-stored-")
    assert "T1" in contrib_json
    assert confidence == "definite"
    # Idempotent.
    again = derive_storage_taint(conn)
    assert again == 0


def test_synthesize_round2_flows_links_dirty_storage_to_reads(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    _seed_round1_users_bio(conn)
    conn.execute("DELETE FROM storage_taint")

    snapshot_root = tmp_path / "source"
    snapshot_root.mkdir()
    (snapshot_root / "reader.js").write_text(
        "const r = await db.query('SELECT bio FROM users WHERE id = 1');\n",
        encoding="utf-8",
    )
    detect_storage_reads(conn, snapshot_root=snapshot_root)
    derive_storage_taint(conn)

    inserted = synthesize_round2_flows(conn)
    assert inserted >= 1
    flows = conn.execute(
        "SELECT fid, tid, sid, cwe, engine, confidence FROM flows WHERE engine = 'storage-taint-r2'"
    ).fetchall()
    assert flows
    fid, tid, sid, cwe, engine, confidence = flows[0]
    assert fid.startswith("f-r2-")
    assert tid.startswith("T-stored-")
    assert sid.startswith("S-r2-")
    assert engine == "storage-taint-r2"
    assert confidence == "inferred"
    assert cwe == "CWE-89"
    # FK rows synthesised.
    assert conn.execute("SELECT 1 FROM taint_sources WHERE tid = ?", [tid]).fetchone() is not None
    assert conn.execute("SELECT 1 FROM taint_sinks WHERE sid = ?", [sid]).fetchone() is not None
    # Idempotent.
    again = synthesize_round2_flows(conn)
    assert again == 0


def test_run_full_fixpoint_terminates_within_3_rounds(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute("INSERT INTO taint_sources VALUES ('T1', NULL, 'http.body', 'name', 'a:1')")
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F1', 'T1', 'K1', 'CWE-89', 'codeql', "
        "'[[\"UPDATE users SET bio = 1\", 1, 1]]', '/sarif', 'definite')"
    )

    snapshot_root = tmp_path / "source"
    snapshot_root.mkdir()
    (snapshot_root / "reader.js").write_text(
        "const r = await db.query('SELECT bio FROM users WHERE id = 1');\n",
        encoding="utf-8",
    )

    stats = run_full_fixpoint(conn, snapshot_root=snapshot_root, max_rounds=3)
    assert stats["rounds_run"] <= 3
    assert stats["rounds_run"] >= 1
    assert stats["new_flows"] >= 1
    assert stats["storage_reads"] >= 1
    assert stats["storage_taint_derived"] >= 1
    # Synthetic round-2 flow row exists.
    r2 = conn.execute("SELECT COUNT(*) FROM flows WHERE engine = 'storage-taint-r2'").fetchone()
    assert r2 is not None and r2[0] >= 1


def test_run_full_fixpoint_no_snapshot_still_runs(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    _seed_round1_users_bio(conn)
    missing = tmp_path / "does-not-exist"
    stats = run_full_fixpoint(conn, snapshot_root=missing, max_rounds=3)
    assert stats["rounds_run"] >= 1
    assert stats["storage_reads"] == 0


# ----------------------------- LLM resolver -----------------------------


def _seed_xref(conn: duckdb.DuckDBPyConnection, file: str, line: int) -> None:
    conn.execute(
        "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?)",
        [None, None, "call", file, line],
    )


def test_find_unresolved_dynamic_calls_picks_template_literals(
    tmp_path: Path,
) -> None:
    src = tmp_path / "svc.ts"
    src.write_text(
        "function setProfile(userId: string, body: any) {\n"
        "  cache.set(`user:${userId}:profile`, body);\n"
        "}\n",
        encoding="utf-8",
    )
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_xref(conn, str(src), 2)

    found = find_unresolved_dynamic_calls(conn, snapshot_root=tmp_path)
    assert len(found) == 1
    f = found[0]
    assert "cache.set" in f.callee
    assert "${userId}" in f.code_snippet


def test_find_unresolved_skips_static_keys(tmp_path: Path) -> None:
    src = tmp_path / "svc.ts"
    src.write_text(
        "cache.set('static-key', body);\n",
        encoding="utf-8",
    )
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_xref(conn, str(src), 1)

    found = find_unresolved_dynamic_calls(conn, snapshot_root=tmp_path)
    assert found == []


def test_merge_proposals_keeps_high_confidence_only(tmp_path: Path) -> None:
    schema_path = tmp_path / "schema.taint.yml"
    schema_path.write_text("tables: {}\n", encoding="utf-8")
    proposals = [
        {
            "call_id": "S-1",
            "storage_id": "cache:user:*:profile",
            "confidence": 0.9,
            "kind": "cache_key",
        },
        {
            "call_id": "S-2",
            "storage_id": "cache:flaky",
            "confidence": 0.2,
            "kind": "cache_key",
        },
        {"call_id": "S-3", "storage_id": None, "confidence": 0.0},
    ]
    merged = merge_proposals_into_schema(schema_path, proposals, min_confidence=0.4)
    assert merged == 1
    body = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    assert "cache:user:*:profile" in body["llm_suggested"]
    assert "cache:flaky" not in body["llm_suggested"]


def test_run_full_fixpoint_seeds_from_llm_suggested(tmp_path: Path) -> None:
    """Round-0: schema's `llm_suggested:` block drives storage→read flows."""
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)

    snapshot_root = tmp_path / "source"
    snapshot_root.mkdir()
    (snapshot_root / "reader.js").write_text(
        "async function loadProfile(userId) {\n  return cache.get(`user:${userId}:profile`);\n}\n",
        encoding="utf-8",
    )

    schema_path = tmp_path / "schema.taint.yml"
    save_schema_yaml(
        schema_path,
        {
            "llm_suggested": {
                "cache:user:*:profile": {
                    "kind": "cache_key",
                    "confidence": 0.9,
                    "rationale": "test",
                    "call_id": "S-test",
                },
            },
        },
    )

    stats = run_full_fixpoint(
        conn,
        snapshot_root=snapshot_root,
        max_rounds=3,
        schema_path=schema_path,
    )

    assert stats["llm_seeded_locations"] == 1
    assert stats["llm_seeded_reads"] >= 1
    locs = conn.execute(
        "SELECT storage_id, kind, schema_evidence FROM storage_locations"
    ).fetchall()
    assert ("cache:user:*:profile", "cache_key", "llm_suggested") in locs
    taint = conn.execute("SELECT storage_id, confidence FROM storage_taint").fetchall()
    assert ("cache:user:*:profile", "llm-suggested") in taint
    r2_flows = conn.execute(
        "SELECT cwe, engine, confidence FROM flows WHERE engine = 'storage-taint-r2'"
    ).fetchall()
    assert r2_flows, "expected at least one round-2 flow seeded by llm_suggested"

    # Idempotent: second run does not re-seed the same locations or reads.
    stats2 = run_full_fixpoint(
        conn,
        snapshot_root=snapshot_root,
        max_rounds=3,
        schema_path=schema_path,
    )
    assert stats2["llm_seeded_locations"] == 0
    assert stats2["llm_seeded_reads"] == 0


def test_run_full_fixpoint_without_llm_suggested_block(tmp_path: Path) -> None:
    """An empty schema is a no-op for the LLM-seed pass."""
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    _seed_round1_users_bio(conn)
    schema_path = tmp_path / "schema.taint.yml"
    save_schema_yaml(schema_path, {"tables": {}})
    stats = run_full_fixpoint(
        conn,
        snapshot_root=tmp_path / "source",
        max_rounds=2,
        schema_path=schema_path,
    )
    assert stats["llm_seeded_locations"] == 0
    assert stats["llm_seeded_reads"] == 0


def test_parse_resolver_proposals_returns_jsonl(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    sr = run_dir / "storage_resolver"
    sr.mkdir(parents=True)
    (sr / "proposals.jsonl").write_text(
        '{"call_id": "S-1", "storage_id": "cache:x", "confidence": 0.8}\n'
        "\n"
        "not-json\n"
        '{"call_id": "S-2", "storage_id": null}\n',
        encoding="utf-8",
    )
    out = parse_resolver_proposals(run_dir)
    assert {p["call_id"] for p in out} == {"S-1", "S-2"}
