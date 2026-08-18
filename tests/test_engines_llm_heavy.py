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


def _flow_row(*, fid: str = "L-001", file: str = "/abs/x.ts") -> dict[str, object]:
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

    flows = tmp_path / "flows.jsonl"
    flows.write_text(
        "\n".join(
            [
                __import__("json").dumps(_flow_row()),
                __import__("json").dumps(_flow_row(fid="L-002", file="/abs/y.ts")),
            ]
        ),
        encoding="utf-8",
    )

    n = ingest_llm_heavy_flows(conn, flows_path=flows)
    assert n == 2
    rows = conn.execute("SELECT engine, cwe FROM flows ORDER BY fid").fetchall()
    assert rows == [("llm-heavy", "CWE-89"), ("llm-heavy", "CWE-89")]
    steps_row = conn.execute("SELECT steps_json FROM flows WHERE fid = 'L-001'").fetchone()
    assert steps_row is not None
    assert json.loads(steps_row[0]) == [
        ["/abs/x.ts", 13, 13],
        ["/abs/x.ts", 42, 42],
    ]
    bundle = extract_slice(conn, flow_id="L-001", context_lines=1)
    assert bundle is not None
    assert [step.line for step in bundle.steps] == [13, 42]


def test_ingest_rejects_invalid_lines(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    flows = tmp_path / "flows.jsonl"
    flows.write_text("not-json\n\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid JSON"):
        ingest_llm_heavy_flows(conn, flows_path=flows)


def test_ingest_missing_file_returns_zero(tmp_path: Path) -> None:
    db = tmp_path / "z.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    assert ingest_llm_heavy_flows(conn, flows_path=tmp_path / "missing.jsonl") == 0


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
        content = "{truncated\n" if attempts == 1 else json.dumps(_flow_row()) + "\n"
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
