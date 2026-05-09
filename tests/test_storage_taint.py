"""Tests for ai_codescan.storage_taint."""

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.storage_taint import (
    classify_call,
    classify_sql_op,
    derive_storage_taint,
    detect_sql_storage_ids,
    detect_storage_reads,
    load_schema_yaml,
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


# ---------------------------------------------------------------------------
# Round-2 tests
# ---------------------------------------------------------------------------


def _seed_round1_users_bio(conn: duckdb.DuckDBPyConnection) -> None:
    """Seed schema + a flow that updates users.bio so storage_writes has content."""
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
    rows = conn.execute(
        "SELECT storage_id, symbol_id FROM storage_reads"
    ).fetchall()
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
        "SELECT storage_id, derived_tid, contributing_tids_json, confidence "
        "FROM storage_taint"
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
        "SELECT fid, tid, sid, cwe, engine, confidence FROM flows "
        "WHERE engine = 'storage-taint-r2'"
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
    assert conn.execute(
        "SELECT 1 FROM taint_sources WHERE tid = ?", [tid]
    ).fetchone() is not None
    assert conn.execute(
        "SELECT 1 FROM taint_sinks WHERE sid = ?", [sid]
    ).fetchone() is not None
    # Idempotent.
    again = synthesize_round2_flows(conn)
    assert again == 0


def test_run_full_fixpoint_terminates_within_3_rounds(tmp_path: Path) -> None:
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
    r2 = conn.execute(
        "SELECT COUNT(*) FROM flows WHERE engine = 'storage-taint-r2'"
    ).fetchone()
    assert r2 is not None and r2[0] >= 1


def test_run_full_fixpoint_no_snapshot_still_runs(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    _seed_round1_users_bio(conn)
    missing = tmp_path / "does-not-exist"
    stats = run_full_fixpoint(conn, snapshot_root=missing, max_rounds=3)
    assert stats["rounds_run"] >= 1
    assert stats["storage_reads"] == 0
