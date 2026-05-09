"""Tests for ai_codescan.storage_taint."""

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.storage_taint import (
    classify_call,
    classify_sql_op,
    detect_sql_storage_ids,
    load_schema_yaml,
    run_fixpoint,
    save_schema_yaml,
)


def test_detect_sql_storage_ids_simple_select() -> None:
    ids = detect_sql_storage_ids("SELECT id, name FROM users WHERE id = 5")
    assert "sql:users.id" in ids
    assert "sql:users.name" in ids


def test_detect_sql_storage_ids_with_alias() -> None:
    ids = detect_sql_storage_ids(
        "SELECT u.bio FROM users u WHERE u.id = 1"
    )
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
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', NULL, 'http.body', 'name', 'a:1')"
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES "
        "('K1', NULL, 'sql.exec', 'pg', 'template-literal', '[]')"
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
