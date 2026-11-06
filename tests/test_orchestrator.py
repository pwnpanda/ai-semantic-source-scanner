"""Unit tests for ai_codescan.runs.orchestrator."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import duckdb
import pytest

from ai_codescan.runs import orchestrator as orchestrator_mod
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


def _write_prep_cache_stage(tmp_path: Path, stage: str = "complete") -> None:
    repo_dir = tmp_path / "repo-x"
    repo_dir.mkdir(exist_ok=True)
    conn = duckdb.connect(str(repo_dir / "index.duckdb"))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_cache_state (
              singleton INTEGER PRIMARY KEY,
              fingerprint VARCHAR,
              engine VARCHAR,
              stage VARCHAR
            )
            """
        )
        conn.execute(
            "INSERT OR REPLACE INTO scan_cache_state VALUES (1, 'fingerprint', 'hybrid', ?)",
            [stage],
        )
    finally:
        conn.close()


def _argv_option(argv: list[str], option: str, default: str = "") -> str:
    return argv[argv.index(option) + 1] if option in argv else default


def _write_nominate_completion(
    tmp_path: Path,
    argv: list[str],
    *,
    candidate_ids: tuple[str, ...] = (),
    completed_ids: set[str] | None = None,
) -> Path:
    run_id = _argv_option(argv, "--run-id")
    run_dir = tmp_path / "repo-x" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run_id,
        "phase": "nominate",
        "llm_provider": _argv_option(argv, "--llm-provider"),
        "llm_model": _argv_option(argv, "--llm-model") or None,
    }
    (run_dir / "run.json").write_text(json.dumps(payload), encoding="utf-8")
    queue = "".join(json.dumps({"id": candidate_id}) + "\n" for candidate_id in candidate_ids)
    (run_dir / "queue.jsonl").write_text(queue, encoding="utf-8")
    nominations = [
        "# Nominations",
        "",
        "## Stream A — Pre-traced",
        "",
        "## Stream B — AI-discovered",
        "",
        "## Stream C — Proposed extensions",
        "",
    ]
    for index, _candidate_id in enumerate(candidate_ids, start=1):
        nominations.append(
            f"- [ ] N-{index:03d} | project | vector | src/Foo.kt:1 | rec: high | y/n: y"
        )
    (run_dir / "nominations.md").write_text("\n".join(nominations) + "\n", encoding="utf-8")
    (run_dir / ".nominate-context").write_text("a" * 64 + "\n", encoding="utf-8")
    done_dir = run_dir / ".done"
    done_dir.mkdir(exist_ok=True)
    for candidate_id in completed_ids if completed_ids is not None else set(candidate_ids):
        (done_dir / candidate_id).touch()
    return run_dir


def _write_analysis_completion(run_dir: Path) -> None:
    (run_dir / "findings_queue.md").write_text(
        "# Findings queue\n\n- [ ] N-001 | project | vector | src/Foo.kt:1\n",
        encoding="utf-8",
    )
    findings_dir = run_dir / "findings"
    findings_dir.mkdir(exist_ok=True)
    (findings_dir / "F-001.md").write_text(
        "---\nfinding_id: F-001\nnomination_id: N-001\nflow_id: flow-1\n"
        "cwe: CWE-79\nstatus: unverified\ntitle: Stored XSS\n---\n\n"
        "## Evidence\n\nUnsanitized value reaches an HTML sink.\n",
        encoding="utf-8",
    )
    done_dir = run_dir / ".done-analyze"
    done_dir.mkdir(exist_ok=True)
    (done_dir / "N-001").write_text("b" * 64 + "\n", encoding="utf-8")


def _write_validation_completion(run_dir: Path) -> None:
    finding_path = run_dir / "findings" / "F-001.md"
    finding_path.write_text(
        "---\nfinding_id: F-001\nnomination_id: N-001\nflow_id: flow-1\n"
        "cwe: CWE-79\nstatus: verified\ntitle: Stored XSS\n---\n\n"
        "## Evidence\n\nThe observation-only PoC confirmed the sink.\n",
        encoding="utf-8",
    )
    marker_dir = run_dir / ".done-validate"
    marker_dir.mkdir(exist_ok=True)
    (marker_dir / "F-001").write_text("c" * 64 + "\n", encoding="utf-8")
    poc_dir = run_dir / "sandbox" / "F-001"
    poc_dir.mkdir(parents=True, exist_ok=True)
    (poc_dir / "poc.py").write_text("print('observation')\n", encoding="utf-8")
    (run_dir / "validation_log.md").write_text(
        "# Validation log\n\n"
        "| finding | status | exit | signal | timed_out | evidence |\n"
        "|---|---|---|---|---|---|\n"
        "| F-001 | verified | exit=0 | signal=n | timed_out=n | evidence=1 |\n",
        encoding="utf-8",
    )


def test_drive_pipeline_runs_each_stage_in_order(tmp_path: Path) -> None:
    seen: list[str] = []

    def runner(argv: list[str]) -> StageOutcome:
        seen.append(argv[3])  # ai-codescan --cache-dir <root> <stage>
        if argv[3] == "prep":
            _write_prep_cache_stage(tmp_path)
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
    assert state.completed == ["prep", "gate-1"]


def test_empty_model_reruns_llm_stage_and_invalidates_downstream(tmp_path: Path) -> None:
    seen: list[str] = []

    def runner(argv: list[str]) -> StageOutcome:
        seen.append(argv[3])
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["nominate", "gate-1"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0

    assert seen == ["nominate", "gate-1", "nominate", "gate-1"]


def test_explicit_model_allows_llm_stage_reuse(tmp_path: Path) -> None:
    calls = 0

    def runner(argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        _write_nominate_completion(tmp_path, argv)
        return StageOutcome(rc=0, stderr="")

    opts = replace(
        _opts(tmp_path, phases=["nominate"]),
        llm_provider="codex",
        llm_model="gpt-5.6-codex",
    )
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0

    assert calls == 1


def test_nominate_run_id_tracks_stage_fingerprint_across_retries(tmp_path: Path) -> None:
    run_ids: list[str] = []
    fail_first = True

    def runner(argv: list[str]) -> StageOutcome:
        nonlocal fail_first
        run_ids.append(argv[argv.index("--run-id") + 1])
        if fail_first:
            fail_first = False
            _write_nominate_completion(
                tmp_path,
                argv,
                candidate_ids=("candidate-1", "candidate-2"),
                completed_ids={"candidate-1"},
            )
            return StageOutcome(rc=2, stderr="partial failure")
        run_dir = tmp_path / "repo-x" / "runs" / run_ids[-1]
        if run_ids[-1] == run_ids[0]:
            assert (run_dir / ".done" / "candidate-1").is_file()
        _write_nominate_completion(
            tmp_path,
            argv,
            candidate_ids=("candidate-1", "candidate-2"),
        )
        return StageOutcome(rc=0, stderr="")

    opts = replace(
        _opts(tmp_path, phases=["nominate"]),
        llm_provider="codex",
        llm_model="gpt-a",
    )
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 2
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    same_attempt_id = run_ids[-1]
    assert run_ids[0] == same_attempt_id

    provider_changed = replace(opts, llm_provider="gemini")
    assert drive_pipeline(provider_changed, runner=runner, asker=lambda _p: "c") == 0
    assert run_ids[-1] != same_attempt_id
    provider_changed_id = run_ids[-1]

    model_changed = replace(provider_changed, llm_model="gemini-b")
    assert drive_pipeline(model_changed, runner=runner, asker=lambda _p: "c") == 0
    assert run_ids[-1] != provider_changed_id
    prior_id = run_ids[-1]

    source = tmp_path / "src"
    source.mkdir()
    (source / "Handler.kt").write_text("fun handler() = 1\n", encoding="utf-8")
    assert drive_pipeline(model_changed, runner=runner, asker=lambda _p: "c") == 0
    assert run_ids[-1] != prior_id
    assert all(re.fullmatch(r"orchestrator-[a-f0-9]{64}", run_id) for run_id in run_ids)


@pytest.mark.parametrize(
    "damage",
    [
        "deleted-run-json",
        "corrupt-queue",
        "corrupt-nominations",
        "missing-context",
        "missing-marker",
    ],
)
def test_nominate_reuse_requires_durable_run_artifacts(tmp_path: Path, damage: str) -> None:
    calls = 0
    run_dir: Path | None = None

    def runner(argv: list[str]) -> StageOutcome:
        nonlocal calls, run_dir
        calls += 1
        run_dir = _write_nominate_completion(
            tmp_path,
            argv,
            candidate_ids=("candidate-1",),
        )
        return StageOutcome(rc=0, stderr="")

    opts = replace(
        _opts(tmp_path, phases=["nominate"]),
        llm_provider="codex",
        llm_model="gpt-a",
    )
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert run_dir is not None
    if damage == "deleted-run-json":
        (run_dir / "run.json").unlink()
    elif damage == "corrupt-queue":
        (run_dir / "queue.jsonl").write_text("{not-json\n", encoding="utf-8")
    elif damage == "corrupt-nominations":
        (run_dir / "nominations.md").write_text("# truncated\n", encoding="utf-8")
    elif damage == "missing-context":
        (run_dir / ".nominate-context").unlink()
    else:
        (run_dir / ".done" / "candidate-1").unlink()

    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert calls == 2


@pytest.mark.parametrize(
    "damage",
    ["deleted-queue", "corrupt-queue", "corrupt-finding", "yaml-finding", "missing-marker"],
)
def test_analyze_reuse_requires_queue_findings_and_markers(tmp_path: Path, damage: str) -> None:
    calls = {"nominate": 0, "analyze": 0}
    run_dir: Path | None = None

    def runner(argv: list[str]) -> StageOutcome:
        nonlocal run_dir
        stage = argv[3]
        calls[stage] += 1
        if stage == "nominate":
            run_dir = _write_nominate_completion(
                tmp_path,
                argv,
                candidate_ids=("candidate-1",),
            )
        else:
            assert run_dir is not None
            _write_analysis_completion(run_dir)
        return StageOutcome(rc=0, stderr="")

    opts = replace(
        _opts(tmp_path, phases=["nominate", "analyze"]),
        llm_provider="codex",
        llm_model="gpt-a",
    )
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert run_dir is not None
    if damage == "deleted-queue":
        (run_dir / "findings_queue.md").unlink()
    elif damage == "corrupt-queue":
        (run_dir / "findings_queue.md").write_text("- [ ] malformed\n", encoding="utf-8")
    elif damage == "corrupt-finding":
        (run_dir / "findings" / "F-001.md").write_text("truncated\n", encoding="utf-8")
    elif damage == "yaml-finding":
        (run_dir / "findings" / "F-001.md").write_text(
            "---\n[unterminated\n---\n\nbody\n",
            encoding="utf-8",
        )
    else:
        (run_dir / ".done-analyze" / "N-001").unlink()

    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert calls == {"nominate": 1, "analyze": 2}


@pytest.mark.parametrize("damage", ["deleted-log", "corrupt-log", "missing-marker", "empty-poc"])
def test_validate_reuse_requires_log_markers_and_pocs(tmp_path: Path, damage: str) -> None:
    calls = {"nominate": 0, "analyze": 0, "validate": 0}
    run_dir: Path | None = None

    def runner(argv: list[str]) -> StageOutcome:
        nonlocal run_dir
        stage = argv[3]
        calls[stage] += 1
        if stage == "nominate":
            run_dir = _write_nominate_completion(
                tmp_path,
                argv,
                candidate_ids=("candidate-1",),
            )
        elif stage == "analyze":
            assert run_dir is not None
            _write_analysis_completion(run_dir)
        else:
            assert run_dir is not None
            _write_validation_completion(run_dir)
        return StageOutcome(rc=0, stderr="")

    opts = replace(
        _opts(tmp_path, phases=["nominate", "analyze", "validate"]),
        llm_provider="codex",
        llm_model="gpt-a",
    )
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert run_dir is not None
    if damage == "deleted-log":
        (run_dir / "validation_log.md").unlink()
    elif damage == "corrupt-log":
        (run_dir / "validation_log.md").write_text("truncated\n", encoding="utf-8")
    elif damage == "missing-marker":
        (run_dir / ".done-validate" / "F-001").unlink()
    else:
        (run_dir / "sandbox" / "F-001" / "poc.py").write_text("", encoding="utf-8")

    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert calls == {"nominate": 1, "analyze": 1, "validate": 2}


@pytest.mark.parametrize("damage", ["deleted-report", "corrupt-report", "deleted-receipt"])
def test_report_reuse_requires_hashed_output_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    damage: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "repo-x" / "runs" / "existing"
    run_dir.mkdir(parents=True)
    _write_analysis_completion(run_dir)
    _write_validation_completion(run_dir)
    calls = 0
    report_path = tmp_path / "report" / "security-review.md"

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        report_path.parent.mkdir(exist_ok=True)
        report_path.write_text(
            "# Stored XSS\n\n## References\n\n- finding_id: `F-001`\n",
            encoding="utf-8",
        )
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["report"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    if damage == "deleted-report":
        report_path.unlink()
    elif damage == "corrupt-report":
        report_path.write_text("truncated\n", encoding="utf-8")
    else:
        (tmp_path / "repo-x" / ".orchestrator-report-artifacts.json").unlink()

    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert calls == 2


def test_zero_finding_report_has_a_reusable_completion_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "repo-x" / "runs" / "existing" / "findings").mkdir(parents=True)
    calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["report"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert calls == 1


def test_one_report_file_cannot_satisfy_two_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "repo-x" / "runs" / "existing"
    run_dir.mkdir(parents=True)
    _write_analysis_completion(run_dir)
    _write_validation_completion(run_dir)
    (run_dir / "findings" / "F-002.md").write_text(
        "---\nfinding_id: F-002\nnomination_id: N-002\nflow_id: flow-2\n"
        "cwe: CWE-89\nstatus: verified\ntitle: SQL injection\n---\n\nEvidence.\n",
        encoding="utf-8",
    )
    calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        report_dir = tmp_path / "report"
        report_dir.mkdir(exist_ok=True)
        (report_dir / "combined.md").write_text(
            "# Combined\n\n- finding_id: `F-001`\n- finding_id: `F-002`\n",
            encoding="utf-8",
        )
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["report"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert calls == 2


@pytest.mark.parametrize("cache_stage", ["prep_with_gaps", "complete_with_gaps"])
def test_prep_with_gaps_is_not_reused_by_outer_pipeline(
    tmp_path: Path,
    cache_stage: str,
) -> None:
    calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        _write_prep_cache_stage(tmp_path, cache_stage)
        return StageOutcome(rc=0, stderr="")

    opts = replace(_opts(tmp_path, phases=["prep"]), engine="hybrid")
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0

    assert calls == 2
    state = load_state(tmp_path, "repo-x")
    assert state is not None
    assert "prep" not in state.completed


@pytest.mark.parametrize("damage", ["deleted", "corrupt", "missing-table", "missing-row"])
def test_prep_requires_an_exact_durable_completion(
    tmp_path: Path,
    damage: str,
) -> None:
    calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        if calls == 1:
            _write_prep_cache_stage(tmp_path)
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["prep"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    db_path = tmp_path / "repo-x" / "index.duckdb"
    if damage == "deleted":
        db_path.unlink()
    elif damage == "corrupt":
        db_path.unlink()
        db_path.write_bytes(b"not a DuckDB database")
    elif damage == "missing-table":
        db_path.unlink()
        duckdb.connect(str(db_path)).close()
    else:
        conn = duckdb.connect(str(db_path))
        try:
            conn.execute("DELETE FROM scan_cache_state")
        finally:
            conn.close()

    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert calls == 2
    state = load_state(tmp_path, "repo-x")
    assert state is not None
    assert "prep" not in state.completed


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
        _write_prep_cache_stage(tmp_path)
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
        _write_prep_cache_stage(tmp_path)
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
        _write_prep_cache_stage(tmp_path)
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
        _write_prep_cache_stage(tmp_path)
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["prep"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    scanner_fingerprint = "rules-v2"
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0

    assert calls == 2


def test_scanner_fingerprint_hashes_runtime_assets_but_not_local_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "package"
    active_files = (
        package_root / "scanner.py",
        package_root / "skills" / "prompt.md",
        package_root / "skills" / "loop.sh",
        package_root / "ast" / "worker.mjs",
        package_root / "codeql" / "query.ql",
        package_root / "codeql" / "library.qll",
    )
    for path in active_files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"initial:{path.name}\n", encoding="utf-8")
    ignored_files = (
        package_root / "node_modules" / "dep" / "package.json",
        package_root / "build" / "generated.json",
        package_root / "fixtures" / "sample.py",
    )
    for path in ignored_files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"initial:{path.name}\n", encoding="utf-8")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    monkeypatch.setattr(orchestrator_mod, "_SCANNER_PACKAGE_ROOT", package_root)

    fingerprint = orchestrator_mod._scanner_configuration_fingerprint(repo_dir)
    for path in ignored_files:
        path.write_text(f"changed:{path.name}\n", encoding="utf-8")
    assert orchestrator_mod._scanner_configuration_fingerprint(repo_dir) == fingerprint

    for path in active_files:
        path.write_text(f"changed:{path.name}\n", encoding="utf-8")
        changed = orchestrator_mod._scanner_configuration_fingerprint(repo_dir)
        assert changed != fingerprint
        fingerprint = changed


def test_drive_pipeline_promoted_semgrep_rule_reruns_completed_stage(tmp_path: Path) -> None:
    rules_dir = tmp_path / "repo-x" / ".semgrep" / "rules"
    rules_dir.mkdir(parents=True)
    rule = rules_dir / "approved.yml"
    rule.write_text("rules:\n  - id: first\n", encoding="utf-8")
    calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal calls
        calls += 1
        _write_prep_cache_stage(tmp_path)
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


# ---------------------------------------------------------------------------
# prep reusability and downstream invalidation (resume safety)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stage", ["prep", "complete"])
def test_prep_cache_is_reusable_for_a_durable_stage(tmp_path: Path, stage: str) -> None:
    _write_prep_cache_stage(tmp_path, stage)
    assert orchestrator_mod._prep_cache_is_reusable(tmp_path / "repo-x") is True


@pytest.mark.parametrize("stage", ["complete_unpinned", "nominate"])
def test_prep_cache_is_not_reusable_without_a_durable_stage(tmp_path: Path, stage: str) -> None:
    """``complete_unpinned`` records a scan built on live registry rules.

    Those flows are not reproducible, so reusing them would mix rule
    generations. Pinning the ruleset is what earns a plain ``complete``.
    """
    _write_prep_cache_stage(tmp_path, stage)
    assert orchestrator_mod._prep_cache_is_reusable(tmp_path / "repo-x") is False


def _prepare_attempt(
    tmp_path: Path, state: OrchestratorState, *, stage: str, scanner_fp: str
) -> str | None:
    repo_dir = tmp_path / "repo-x"
    return orchestrator_mod._prepare_stage_attempt(
        state,
        _opts(tmp_path, phases=[stage]),
        stage=stage,
        repo_dir=repo_dir,
        fingerprints=("source-fp", scanner_fp),
    )


def _seed_downstream_markers(tmp_path: Path) -> tuple[Path, Path]:
    """Create a run dir holding completed nominate work."""
    repo_dir = tmp_path / "repo-x"
    run_dir = repo_dir / "runs" / "orchestrator-abc"
    (run_dir / ".done").mkdir(parents=True)
    (run_dir / ".done" / "A-joern-1234").write_text("", encoding="utf-8")
    nominations = run_dir / "nominations.md"
    nominations.write_text("# Nominations\n\n- one\n", encoding="utf-8")
    return run_dir / ".done" / "A-joern-1234", nominations


def test_rerunning_prep_with_unchanged_inputs_keeps_nominate_progress(tmp_path: Path) -> None:
    """A resume must not discard completed LLM work.

    Regression: prep re-ran on every resume and unconditionally invalidated
    downstream, deleting hundreds of finished nominations that were still
    valid. Nominate markers are content-addressed, so stale ones simply fail
    to match and are redone.
    """
    _write_prep_cache_stage(tmp_path, "complete_unpinned")
    marker, nominations = _seed_downstream_markers(tmp_path)
    state = OrchestratorState(repo_id="repo-x", target=str(tmp_path / "src"), phases=["prep"])
    # Same fingerprint as the attempt below, and nominate failed part-way.
    fingerprint = _prepare_attempt(tmp_path, state, stage="prep", scanner_fp="scanner-fp")
    assert fingerprint is not None

    state.stage_fingerprints["prep"] = fingerprint
    state.last_error = "nominate: rc=1"
    _prepare_attempt(tmp_path, state, stage="prep", scanner_fp="scanner-fp")

    assert marker.is_file(), "completed nomination marker was deleted on resume"
    assert nominations.is_file(), "nominations.md was deleted on resume"


def test_rerunning_prep_with_changed_inputs_invalidates_nominate(tmp_path: Path) -> None:
    """A real input change still invalidates downstream work."""
    _write_prep_cache_stage(tmp_path, "complete_unpinned")
    marker, nominations = _seed_downstream_markers(tmp_path)
    state = OrchestratorState(repo_id="repo-x", target=str(tmp_path / "src"), phases=["prep"])
    state.stage_fingerprints["prep"] = "a-different-fingerprint"

    _prepare_attempt(tmp_path, state, stage="prep", scanner_fp="scanner-fp")

    assert not marker.exists(), "stale marker survived a genuine input change"
    assert not nominations.exists()


def test_registry_snapshot_is_part_of_the_scanner_fingerprint(tmp_path: Path) -> None:
    """Refreshing pinned rules must invalidate downstream work.

    The snapshot is a prep input: if it changed without changing the
    fingerprint, nominations built on the old ruleset would be kept.
    """
    repo_dir = tmp_path / "repo-x"
    repo_dir.mkdir()
    before = orchestrator_mod._scanner_configuration_fingerprint(repo_dir)

    snapshot = orchestrator_mod.semgrep_engine.registry_snapshot_path(repo_dir)
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text("rules:\n- id: refreshed\n", encoding="utf-8")
    after = orchestrator_mod._scanner_configuration_fingerprint(repo_dir)

    assert before != after


def test_fresh_cache_snapshot_does_not_rerun_prep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator_mod.semgrep_engine,
        "_fetch_registry_ruleset",
        lambda _ref: "rules:\n- id: pinned\n",
    )
    prep_calls = 0

    def runner(_argv: list[str]) -> StageOutcome:
        nonlocal prep_calls
        prep_calls += 1
        orchestrator_mod.semgrep_engine.ensure_registry_snapshot(tmp_path / "repo-x")
        _write_prep_cache_stage(tmp_path)
        return StageOutcome(rc=0, stderr="")

    opts = _opts(tmp_path, phases=["prep"])
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0
    assert drive_pipeline(opts, runner=runner, asker=lambda _p: "c") == 0

    assert prep_calls == 1
