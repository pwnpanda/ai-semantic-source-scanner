"""Tests for ai_codescan.runs.state."""

from pathlib import Path

from ai_codescan.runs.state import (
    RunState,
    load_or_create,
    record_call,
    save,
)


def test_load_or_create_creates_new(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=0.0,
        target_bug_classes=["xss"],
    )
    assert isinstance(state, RunState)
    assert state.engine == "codeql"
    assert state.run_dir.parent == repo_dir / "runs"


def test_record_call_accumulates_cost(tmp_path: Path) -> None:
    repo_dir = tmp_path / "r"
    repo_dir.mkdir()
    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=0.0,
        target_bug_classes=[],
    )
    record_call(
        state,
        step="nominator",
        model="claude-sonnet-4-6",
        input_tokens=1000,
        cache_read=0,
        output_tokens=200,
        usd=0.05,
    )
    record_call(
        state,
        step="nominator",
        model="claude-sonnet-4-6",
        input_tokens=500,
        cache_read=400,
        output_tokens=100,
        usd=0.01,
    )
    save(state)
    assert abs(state.total_usd - 0.06) < 1e-9
    assert len(state.calls) == 2


def test_save_then_reload_preserves_state(tmp_path: Path) -> None:
    repo_dir = tmp_path / "r"
    repo_dir.mkdir()
    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=0.3,
        target_bug_classes=["xss", "sqli"],
    )
    record_call(state, step="x", model="m", input_tokens=1, cache_read=0, output_tokens=1, usd=0.01)
    save(state)

    reloaded = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=0.3,
        target_bug_classes=["xss", "sqli"],
        run_id=state.run_id,
    )
    assert reloaded.run_id == state.run_id
    assert reloaded.calls and reloaded.calls[0]["step"] == "x"
