"""Unit tests for ai_codescan.runs.orchestrator."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from ai_codescan.runs.orchestrator import (
    PIPELINE_STAGES,
    DriveOptions,
    OrchestratorState,
    Prompt,
    StageOutcome,
    ask,
    count_artifacts,
    detect_rate_limit_or_auth,
    drive_pipeline,
    load_state,
    preflight_llm_choice,
    save_state,
    select_phases,
    state_path,
)

# ---------------------------------------------------------------------------
# select_phases
# ---------------------------------------------------------------------------


def test_select_phases_default_returns_full_pipeline() -> None:
    assert select_phases() == list(PIPELINE_STAGES)


def test_select_phases_explicit_list_preserves_order() -> None:
    assert select_phases(phases="prep,nominate,gate-1") == ["prep", "nominate", "gate-1"]


def test_select_phases_unknown_phase_raises() -> None:
    with pytest.raises(ValueError, match="bogus"):
        select_phases(phases="prep,bogus")


def test_select_phases_from_to_slices_inclusive() -> None:
    assert select_phases(start_at="nominate", stop_at="analyze") == [
        "nominate",
        "gate-1",
        "analyze",
    ]


def test_select_phases_from_after_to_raises() -> None:
    with pytest.raises(ValueError, match="comes after"):
        select_phases(start_at="analyze", stop_at="prep")


# ---------------------------------------------------------------------------
# detect_rate_limit_or_auth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stderr",
    [
        "HTTP 429 too many requests",
        "Anthropic rate-limit hit, retry after 30s",
        "Error: invalid api key",
        "401 Unauthorized",
        "please log in to continue",
        "claude: not logged in",
    ],
)
def test_detect_rate_limit_or_auth_matches(stderr: str) -> None:
    assert detect_rate_limit_or_auth(stderr) is True


@pytest.mark.parametrize(
    "stderr",
    [
        "",
        "ImportError: no module named foo",
        "duckdb: file not found",
        "tree-sitter: parser missing",
    ],
)
def test_detect_rate_limit_or_auth_skips_unrelated(stderr: str) -> None:
    assert detect_rate_limit_or_auth(stderr) is False


# ---------------------------------------------------------------------------
# state save / load round-trip
# ---------------------------------------------------------------------------


def test_state_round_trip(tmp_path: Path) -> None:
    state = OrchestratorState(
        repo_id="abc123",
        target="/tmp/sample",
        phases=["prep", "nominate"],
        completed=["prep"],
        stage_fingerprints={"prep": "fingerprint"},
        last_error=None,
        decisions={"nominate:zero_output": "c"},
    )
    save_state(tmp_path, state)
    p = state_path(tmp_path, "abc123")
    assert p.is_file()
    loaded = load_state(tmp_path, "abc123")
    assert loaded == state


def test_load_state_returns_none_when_missing(tmp_path: Path) -> None:
    assert load_state(tmp_path, "nope") is None


# ---------------------------------------------------------------------------
# ask
# ---------------------------------------------------------------------------


def test_ask_returns_typed_choice() -> None:
    prompt = Prompt(
        question="pick one",
        flag_hint="--foo bar",
        options={"a": "alpha", "b": "beta"},
        default="a",
    )
    out = ask(prompt, input_fn=lambda _msg: "b", bell_fn=lambda: None)
    assert out == "b"


def test_ask_falls_back_to_default_on_empty() -> None:
    prompt = Prompt(
        question="pick one",
        flag_hint="--foo bar",
        options={"a": "alpha", "b": "beta"},
        default="a",
    )
    out = ask(prompt, input_fn=lambda _msg: "", bell_fn=lambda: None)
    assert out == "a"


def test_ask_rejects_unknown_input_falls_back_to_default() -> None:
    prompt = Prompt(
        question="pick one",
        flag_hint="--foo bar",
        options={"a": "alpha", "b": "beta"},
        default="a",
    )
    out = ask(prompt, input_fn=lambda _msg: "zzz", bell_fn=lambda: None)
    assert out == "a"


# ---------------------------------------------------------------------------
# count_artifacts
# ---------------------------------------------------------------------------


def test_count_artifacts_returns_minus_one_for_gates(tmp_path: Path) -> None:
    for stage in ("prep", "gate-1", "gate-2", "gate-3"):
        assert count_artifacts(tmp_path, stage) == -1


def test_count_artifacts_nominate_counts_bullets(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "abcd"
    run_dir.mkdir(parents=True)
    (run_dir / "nominations.md").write_text(
        "# Nominations\n\n- flow-1: SQLi\n- flow-2: XSS\nrandom prose\n",
        encoding="utf-8",
    )
    assert count_artifacts(tmp_path, "nominate") == 2


def test_count_artifacts_nominate_zero_when_no_runs(tmp_path: Path) -> None:
    assert count_artifacts(tmp_path, "nominate") == 0


def test_count_artifacts_validate_only_counts_verified(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "abcd"
    findings = run_dir / "findings"
    findings.mkdir(parents=True)
    (findings / "ok.md").write_text("status: verified\nbody\n", encoding="utf-8")
    (findings / "rejected.md").write_text("status: false-positive\nbody\n", encoding="utf-8")
    (findings / "pending.md").write_text("status: unverified\nbody\n", encoding="utf-8")
    assert count_artifacts(tmp_path, "validate") == 1


# ---------------------------------------------------------------------------
# preflight_llm_choice
# ---------------------------------------------------------------------------


def test_preflight_yes_short_circuits() -> None:
    out = preflight_llm_choice(provider_supplied=False, model_supplied=False, yes=True)
    assert out == (None, None)


def test_preflight_returns_provider_choice() -> None:
    out = preflight_llm_choice(
        provider_supplied=False,
        model_supplied=True,
        yes=False,
        asker=lambda _p: "g",
    )
    assert out == ("gemini", None)


def test_preflight_skips_when_both_supplied() -> None:
    out = preflight_llm_choice(
        provider_supplied=True,
        model_supplied=True,
        yes=False,
        asker=lambda _p: pytest.fail("should not be asked"),  # type: ignore[arg-type,return-value]
    )
    assert out == (None, None)


# ---------------------------------------------------------------------------
# drive_pipeline
# ---------------------------------------------------------------------------


def _opts(tmp_path: Path, *, phases: list[str], yes: bool = True) -> DriveOptions:
    return DriveOptions(
        cache_root=tmp_path,
        target=tmp_path / "src",
        repo_id="repo-x",
        phases=phases,
        llm_provider="claude",
        llm_model="",
        temperature=0.0,
        target_bug_class="",
        commit="",
        yes=yes,
        no_sandbox=False,
        bugbounty=False,
    )


def test_drive_pipeline_runs_each_stage_in_order(tmp_path: Path) -> None:
    seen: list[str] = []

    def runner(argv: list[str]) -> StageOutcome:
        seen.append(argv[3])  # ai-codescan --cache-dir <root> <stage>
        return StageOutcome(rc=0, stderr="")

    rc = drive_pipeline(
        _opts(tmp_path, phases=["prep", "nominate", "gate-1"]),
        runner=runner,
        asker=lambda _p: "c",
    )
    assert rc == 0
    assert seen == ["prep", "nominate", "gate-1"]
    state = load_state(tmp_path, "repo-x")
    assert state is not None
    assert state.completed == ["prep", "nominate", "gate-1"]


def test_drive_pipeline_forwards_codex_config_to_llm_heavy_prep(tmp_path: Path) -> None:
    seen: list[str] = []

    def runner(argv: list[str]) -> StageOutcome:
        seen.extend(argv)
        return StageOutcome(rc=0, stderr="")

    opts = replace(
        _opts(tmp_path, phases=["prep"]),
        engine="llm-heavy",
        llm_provider="codex",
        llm_model="gpt-5.6",
    )
    assert drive_pipeline(opts, runner=runner, asker=lambda _prompt: "c") == 0
    assert seen[seen.index("--engine") + 1] == "llm-heavy"
    assert seen[seen.index("--llm-provider") + 1] == "codex"
    assert seen[seen.index("--llm-model") + 1] == "gpt-5.6"


def test_drive_pipeline_skips_completed_stages_on_resume(tmp_path: Path) -> None:
    first_seen: list[str] = []

    def first_runner(argv: list[str]) -> StageOutcome:
        first_seen.append(argv[3])
        return StageOutcome(rc=0, stderr="")

    drive_pipeline(
        _opts(tmp_path, phases=["prep"]),
        runner=first_runner,
        asker=lambda _p: "c",
    )
    assert first_seen == ["prep"]

    seen: list[str] = []

    def runner(argv: list[str]) -> StageOutcome:
        seen.append(argv[3])
        return StageOutcome(rc=0, stderr="")

    drive_pipeline(
        _opts(tmp_path, phases=["prep", "nominate"]),
        runner=runner,
        asker=lambda _p: "c",
    )
    assert seen == ["nominate"]


def test_drive_pipeline_provider_change_reruns_llm_stage(tmp_path: Path) -> None:
    seen: list[str] = []

    def runner(argv: list[str]) -> StageOutcome:
        seen.append(argv[argv.index("--llm-provider") + 1])
        return StageOutcome(rc=0, stderr="")

    claude = _opts(tmp_path, phases=["nominate"])
    codex = replace(claude, llm_provider="codex", llm_model="gpt-5.6-codex")

    assert drive_pipeline(claude, runner=runner, asker=lambda _p: "c") == 0
    assert drive_pipeline(codex, runner=runner, asker=lambda _p: "c") == 0

    assert seen == ["claude", "codex"]


def test_changed_analyze_attempt_clears_inner_completion_markers(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    source_file = source / "handler.kt"
    source_file.write_text("fun handler() = 1\n", encoding="utf-8")
    marker_dir = tmp_path / "repo-x" / "runs" / "run-1" / ".done-analyze"
    marker_dir.mkdir(parents=True)
    marker = marker_dir / "N-001"
    calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        if calls == 1:
            marker.write_text("old-attempt", encoding="utf-8")
            return StageOutcome(rc=2, stderr="failed")
        assert not marker.exists()
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["analyze"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 2
    source_file.write_text("fun handler() = 2\n", encoding="utf-8")
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert calls == 2


def test_drive_pipeline_source_change_reruns_completed_stage(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    source_file = source / "handler.kt"
    source_file.write_text("fun handler() = 1\n", encoding="utf-8")
    calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["prep"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    source_file.write_text("fun handler() = 2\n", encoding="utf-8")
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0

    assert calls == 2


def test_drive_pipeline_dirty_git_source_reruns_completed_stage(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    source_file = source / "handler.kt"
    source_file.write_text("fun handler() = 1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "handler.kt"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "initial",
        ],
        check=True,
    )
    calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["prep"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    source_file.write_text("fun handler() = 2\n", encoding="utf-8")
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0

    assert calls == 2


def test_drive_pipeline_scanner_change_reruns_completed_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner_fingerprint = "rules-v1"
    monkeypatch.setattr(
        "ai_codescan.runs.orchestrator._scanner_configuration_fingerprint",
        lambda _repo_dir: scanner_fingerprint,
    )
    calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["prep"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    scanner_fingerprint = "rules-v2"
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0

    assert calls == 2


def test_drive_pipeline_promoted_semgrep_rule_reruns_completed_stage(tmp_path: Path) -> None:
    rules_dir = tmp_path / "repo-x" / ".semgrep" / "rules"
    rules_dir.mkdir(parents=True)
    rule = rules_dir / "approved.yml"
    rule.write_text("rules:\n  - id: first\n", encoding="utf-8")
    calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["prep"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    rule.write_text("rules:\n  - id: second\n", encoding="utf-8")
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0

    assert calls == 2


def test_drive_pipeline_aborts_on_non_zero_when_no_rate_limit(tmp_path: Path) -> None:
    def runner(_argv: list[str]) -> StageOutcome:
        return StageOutcome(rc=2, stderr="parser exploded\n")

    rc = drive_pipeline(
        _opts(tmp_path, phases=["prep"]),
        runner=runner,
        asker=lambda _p: pytest.fail("should not be asked"),  # type: ignore[arg-type,return-value]
    )
    assert rc == 2
    state = load_state(tmp_path, "repo-x")
    assert state is not None
    assert state.last_error == "prep: rc=2"
    assert "prep" not in state.completed


def test_drive_pipeline_prompts_on_rate_limit_and_retries(tmp_path: Path) -> None:
    calls = {"n": 0}

    def runner(_argv: list[str]) -> StageOutcome:
        calls["n"] += 1
        if calls["n"] == 1:
            return StageOutcome(rc=1, stderr="HTTP 429 rate-limit\n")
        # Make the retry "produce" artefacts so the zero-output prompt
        # doesn't fire.
        run_dir = tmp_path / "repo-x" / "runs" / "abcd"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "nominations.md").write_text("- f1\n- f2\n", encoding="utf-8")
        return StageOutcome(rc=0, stderr="")

    asks: list[str] = []

    def asker(prompt: Prompt) -> str:
        asks.append(prompt.question)
        return "r"  # retry

    opts = replace(_opts(tmp_path, phases=["nominate"]), yes=False)
    rc = drive_pipeline(opts, runner=runner, asker=asker)
    assert rc == 0
    assert calls["n"] == 2
    assert any("rate-limit" in q for q in asks)


def test_drive_pipeline_zero_output_aborts_when_user_says_so(tmp_path: Path) -> None:
    def runner(_argv: list[str]) -> StageOutcome:
        return StageOutcome(rc=0, stderr="")

    # ``nominate`` with no nominations.md → count_artifacts returns 0.
    opts = replace(_opts(tmp_path, phases=["nominate"]), yes=False)
    rc = drive_pipeline(opts, runner=runner, asker=lambda _p: "a")
    assert rc == 0
    state = load_state(tmp_path, "repo-x")
    assert state is not None
    assert state.last_error == "nominate: aborted on zero output"


# ---------------------------------------------------------------------------
# Sanity: callable signatures stay stable
# ---------------------------------------------------------------------------


def test_runner_signature_is_callable_returning_outcome() -> None:
    """Future refactors must keep ``runner: Callable[[list[str]], StageOutcome]``."""

    def runner(_argv: list[str]) -> StageOutcome:
        return StageOutcome(rc=0, stderr="")

    typed: Callable[[list[str]], StageOutcome] = runner
    assert isinstance(typed([]), StageOutcome)
