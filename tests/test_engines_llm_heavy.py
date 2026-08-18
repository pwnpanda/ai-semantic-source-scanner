"""Tests for ai_codescan.engines.llm_heavy."""

import json
from pathlib import Path

import duckdb
import pytest

from ai_codescan.cache_state import set_scan_stage
from ai_codescan.engines import llm_heavy as llm_heavy_mod
from ai_codescan.engines.llm_heavy import ingest_llm_heavy_flows
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.llm import LLMConfig
from ai_codescan.runs.state import load_or_create
from ai_codescan.slice import extract_slice


def _flow_row(*, file: str, fid: str = "L-001") -> dict[str, object]:
    return {
        "fid": fid,
        "cwe": "CWE-89",
        "source": {"file": file, "line": 13, "class": "http.body", "key": "name"},
        "sink": {"file": file, "line": 42, "class": "sql.exec", "lib": "pg"},
        "steps": [{"file": file, "line": 13}, {"file": file, "line": 42}],
    }


def test_ingest_llm_heavy_flows_inserts_rows(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    source_root = tmp_path / "source"
    source_root.mkdir()
    x_source = source_root / "x.ts"
    y_source = source_root / "y.ts"
    source_text = "\n".join(f"line {line}" for line in range(1, 50)) + "\n"
    x_source.write_text(source_text, encoding="utf-8")
    y_source.write_text(source_text, encoding="utf-8")

    flows = tmp_path / "flows.jsonl"
    flows.write_text(
        "\n".join(
            [
                __import__("json").dumps(_flow_row(file="x.ts")),
                __import__("json").dumps(_flow_row(fid="L-002", file=y_source.as_posix())),
            ]
        ),
        encoding="utf-8",
    )

    n = ingest_llm_heavy_flows(conn, flows_path=flows, source_root=source_root)
    assert n == 2
    rows = conn.execute("SELECT engine, cwe FROM flows ORDER BY fid").fetchall()
    assert rows == [("llm-heavy", "CWE-89"), ("llm-heavy", "CWE-89")]
    steps_row = conn.execute("SELECT steps_json FROM flows WHERE fid = 'L-001'").fetchone()
    assert steps_row is not None
    assert json.loads(steps_row[0]) == [
        [x_source.as_posix(), 13, 13],
        [x_source.as_posix(), 42, 42],
    ]
    bundle = extract_slice(
        conn,
        flow_id="L-001",
        source_root=source_root,
        context_lines=1,
    )
    assert bundle is not None
    assert [step.line for step in bundle.steps] == [13, 42]


def test_ingest_rejects_invalid_lines(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    flows = tmp_path / "flows.jsonl"
    flows.write_text("not-json\n\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid JSON"):
        ingest_llm_heavy_flows(conn, flows_path=flows, source_root=tmp_path)


def test_ingest_missing_file_returns_zero(tmp_path: Path) -> None:
    db = tmp_path / "z.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    assert (
        ingest_llm_heavy_flows(
            conn,
            flows_path=tmp_path / "missing.jsonl",
            source_root=tmp_path,
        )
        == 0
    )


@pytest.mark.parametrize("bad_path", ("/etc/passwd", "../outside.ts", "linked.ts"))
def test_ingest_rejects_source_paths_outside_snapshot(
    tmp_path: Path,
    bad_path: str,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    valid = source_root / "valid.ts"
    valid.write_text("source();\nsink();\n", encoding="utf-8")
    outside = tmp_path / "outside.ts"
    outside.write_text("outside sentinel\n", encoding="utf-8")
    (source_root / "linked.ts").symlink_to(outside)
    row = _flow_row(file=bad_path)
    row["sink"] = {"file": valid.as_posix(), "line": 2, "class": "sql.exec"}
    row["steps"] = [
        {"file": bad_path, "line": 13},
        {"file": valid.as_posix(), "line": 2},
    ]
    flows = tmp_path / "flows.jsonl"
    flows.write_text(json.dumps(row) + "\n", encoding="utf-8")
    conn = duckdb.connect(str(tmp_path / "contained.duckdb"))
    apply_schema(conn)

    with pytest.raises(RuntimeError, match=r"invalid source\.file.*escapes snapshot"):
        ingest_llm_heavy_flows(conn, flows_path=flows, source_root=source_root)

    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (0,)
    assert conn.execute("SELECT COUNT(*) FROM taint_sources").fetchone() == (0,)
    assert conn.execute("SELECT COUNT(*) FROM taint_sinks").fetchone() == (0,)


def test_ingest_validates_all_paths_before_inserting_any_flow(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    valid = source_root / "valid.ts"
    valid.write_text("\n" * 50, encoding="utf-8")
    flows = tmp_path / "flows.jsonl"
    flows.write_text(
        json.dumps(_flow_row(file=valid.as_posix()))
        + "\n"
        + json.dumps(_flow_row(file="/etc/passwd", fid="poisoned"))
        + "\n",
        encoding="utf-8",
    )
    conn = duckdb.connect(str(tmp_path / "transactional.duckdb"))
    apply_schema(conn)

    with pytest.raises(RuntimeError, match="escapes snapshot"):
        ingest_llm_heavy_flows(conn, flows_path=flows, source_root=source_root)

    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (0,)
    assert conn.execute("SELECT COUNT(*) FROM taint_sources").fetchone() == (0,)
    assert conn.execute("SELECT COUNT(*) FROM taint_sinks").fetchone() == (0,)


def test_ingest_requires_steps_to_match_source_and_sink(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "flow.ts"
    source.write_text("source();\nsink();\n", encoding="utf-8")
    row = _flow_row(file=source.as_posix())
    row["steps"] = [
        {"file": source.as_posix(), "line": 12},
        {"file": source.as_posix(), "line": 42},
    ]
    flows = tmp_path / "flows.jsonl"
    flows.write_text(json.dumps(row) + "\n", encoding="utf-8")
    conn = duckdb.connect(str(tmp_path / "mismatch.duckdb"))
    apply_schema(conn)

    with pytest.raises(RuntimeError, match="first step must match source"):
        ingest_llm_heavy_flows(conn, flows_path=flows, source_root=source_root)


def test_run_llm_heavy_uses_requested_codex_provider_and_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "source").mkdir()
    db_path = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    set_scan_stage(conn, fingerprint="codex-inputs", engine="llm-heavy", stage="prep")
    conn.close()
    state = load_or_create(
        repo_dir,
        engine="llm-heavy",
        temperature=0.0,
        target_bug_classes=[],
        llm_provider="codex",
        llm_model="gpt-5.6",
    )
    captured: list[LLMConfig] = []
    captured_env: dict[str, str] = {}
    captured_cwd: list[Path] = []

    def fake_script(path: Path, config: LLMConfig) -> Path:
        captured.append(config)
        return path

    def fake_run(*_args, **kwargs) -> None:
        captured_env.update(kwargs["env"])
        captured_cwd.append(kwargs["cwd"])

    monkeypatch.setattr(llm_heavy_mod, "is_available", lambda provider: provider == "codex")
    monkeypatch.setattr(llm_heavy_mod, "write_llm_cmd_script", fake_script)
    monkeypatch.setattr(llm_heavy_mod.subprocess, "run", fake_run)

    count = llm_heavy_mod.run_llm_heavy_engine(
        state,
        repo_dir=repo_dir,
        db_path=db_path,
        llm=LLMConfig(provider="codex", model="gpt-5.6"),
        scan_fingerprint="codex-inputs",
    )

    assert count == 0
    assert captured == [LLMConfig(provider="codex", model="gpt-5.6")]
    source_root = Path(captured_env["AI_CODESCAN_SOURCE_ROOT"])
    assert source_root == repo_dir / "source"
    assert source_root.is_dir()
    assert captured_cwd == [source_root]
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        assert conn.execute("SELECT engine, stage FROM scan_cache_state").fetchone() == (
            "llm-heavy",
            "complete",
        )
    finally:
        conn.close()


def test_run_llm_heavy_invalid_output_stays_incomplete_then_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    source_root = repo_dir / "source"
    source_root.mkdir(parents=True)
    source_file = source_root / "x.ts"
    source_file.write_text("\n" * 50, encoding="utf-8")
    db_path = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    set_scan_stage(conn, fingerprint="codex-inputs", engine="llm-heavy", stage="prep")
    conn.close()
    state = load_or_create(
        repo_dir,
        engine="llm-heavy",
        temperature=0.0,
        target_bug_classes=[],
        llm_provider="codex",
        llm_model="gpt-5.6",
    )
    attempts = 0

    def fake_run(*_args, **kwargs) -> None:
        nonlocal attempts
        attempts += 1
        flows = Path(kwargs["env"]["AI_CODESCAN_RUN_DIR"]) / "llm_heavy_flows.jsonl"
        content = (
            "{truncated\n"
            if attempts == 1
            else json.dumps(_flow_row(file=source_file.as_posix())) + "\n"
        )
        flows.write_text(content, encoding="utf-8")

    monkeypatch.setattr(llm_heavy_mod, "is_available", lambda _provider: True)
    monkeypatch.setattr(llm_heavy_mod, "write_llm_cmd_script", lambda path, _config: path)
    monkeypatch.setattr(llm_heavy_mod.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="invalid JSON"):
        llm_heavy_mod.run_llm_heavy_engine(
            state,
            repo_dir=repo_dir,
            db_path=db_path,
            scan_fingerprint="codex-inputs",
        )
    conn = duckdb.connect(str(db_path), read_only=True)
    assert conn.execute("SELECT stage FROM scan_cache_state").fetchone() == ("prep",)
    conn.close()

    count = llm_heavy_mod.run_llm_heavy_engine(
        state,
        repo_dir=repo_dir,
        db_path=db_path,
        scan_fingerprint="codex-inputs",
    )
    assert count == 1
    conn = duckdb.connect(str(db_path), read_only=True)
    assert conn.execute("SELECT stage FROM scan_cache_state").fetchone() == ("complete",)
    conn.close()


def test_run_llm_heavy_default_model_completion_is_not_reusable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    (repo_dir / "source").mkdir(parents=True)
    db_path = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    set_scan_stage(conn, fingerprint="codex-inputs", engine="llm-heavy", stage="prep")
    conn.close()
    state = load_or_create(
        repo_dir,
        engine="llm-heavy",
        temperature=0.0,
        target_bug_classes=[],
        llm_provider="codex",
    )
    attempts = 0

    def fake_run(*_args, **_kwargs) -> None:
        nonlocal attempts
        attempts += 1

    monkeypatch.setattr(llm_heavy_mod, "is_available", lambda _provider: True)
    monkeypatch.setattr(llm_heavy_mod, "write_llm_cmd_script", lambda path, _config: path)
    monkeypatch.setattr(llm_heavy_mod.subprocess, "run", fake_run)

    llm_heavy_mod.run_llm_heavy_engine(
        state,
        repo_dir=repo_dir,
        db_path=db_path,
        scan_fingerprint="codex-inputs",
    )
    conn = duckdb.connect(str(db_path))
    assert conn.execute("SELECT stage FROM scan_cache_state").fetchone() == ("complete_unpinned",)
    set_scan_stage(conn, fingerprint="codex-inputs", engine="llm-heavy", stage="prep")
    conn.close()
    llm_heavy_mod.run_llm_heavy_engine(
        state,
        repo_dir=repo_dir,
        db_path=db_path,
        scan_fingerprint="codex-inputs",
    )
    assert attempts == 2


def test_run_llm_heavy_missing_requested_provider_stays_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    db_path = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    set_scan_stage(conn, fingerprint="codex-inputs", engine="llm-heavy", stage="prep")
    conn.close()
    state = load_or_create(
        repo_dir,
        engine="llm-heavy",
        temperature=0.0,
        target_bug_classes=[],
        llm_provider="codex",
    )
    monkeypatch.setattr(llm_heavy_mod, "is_available", lambda _provider: False)

    with pytest.raises(RuntimeError, match="'codex'.*not available"):
        llm_heavy_mod.run_llm_heavy_engine(
            state,
            repo_dir=repo_dir,
            db_path=db_path,
            scan_fingerprint="codex-inputs",
        )

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        assert conn.execute("SELECT stage FROM scan_cache_state").fetchone() == ("prep",)
    finally:
        conn.close()


def test_run_llm_heavy_rejects_incomplete_prep_marker(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    db_path = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    set_scan_stage(conn, fingerprint="codex-inputs", engine="llm-heavy", stage="prep")
    conn.close()
    (repo_dir / ".prep-incomplete").write_text("in progress\n", encoding="utf-8")
    state = load_or_create(
        repo_dir,
        engine="llm-heavy",
        temperature=0.0,
        target_bug_classes=[],
        llm_provider="codex",
    )

    with pytest.raises(RuntimeError, match="prep is incomplete"):
        llm_heavy_mod.run_llm_heavy_engine(
            state,
            repo_dir=repo_dir,
            db_path=db_path,
            scan_fingerprint="codex-inputs",
        )
