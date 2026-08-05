"""Tests for ai_codescan.adversarial_validator — Phase 13 adversarial validation."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import duckdb

from ai_codescan import adversarial_validator as av
from ai_codescan.adversarial_validator import (
    AdversarialChallenge,
    ChallengeConsensus,
    adversarial_score_delta,
    build_challenge_prompt,
    challenge_consensus_all,
    challenge_verdicts,
    load_review_verdicts,
    make_adversarial_challenger,
    parse_challenge_output,
    persist_adversarial_challenges,
    reachability_note,
    summarize_challenges,
    with_reachability_evidence,
)
from ai_codescan.llm import LLMConfig
from ai_codescan.review_verdicts import ReviewVerdict, persist_review_verdicts


def _verdict(
    *,
    finding_id: str = "F-1",
    verdict: str = "true-positive",
    reviewer: str = "deep_analyzer",
) -> ReviewVerdict:
    return ReviewVerdict(
        nomination_id="N-1",
        finding_id=finding_id,
        flow_id="flow-1",
        candidate_id="cand-1",
        verdict=verdict,
        status="verified",
        confidence="high",
        cwe="CWE-89",
        title="SQL injection in user lookup",
        evidence=["src/users.py:42 concatenates request.args into SQL"],
        reviewer=reviewer,
        source_path="findings/F-1.md",
    )


# --- parse_challenge_output ---------------------------------------------------


def test_parse_challenge_output_parses_json() -> None:
    raw = '{"result": "disputed", "rationale": "the ORM escapes this"}'
    assert parse_challenge_output(raw) == ("disputed", "the ORM escapes this")


def test_parse_challenge_output_finds_json_in_prose() -> None:
    raw = 'Here is my answer:\n{"result": "confirmed", "rationale": "no sanitizer"}\nDone.'
    assert parse_challenge_output(raw) == ("confirmed", "no sanitizer")


def test_parse_challenge_output_token_fallback() -> None:
    """A model that ignored the JSON instruction still names a result word."""
    result = parse_challenge_output("After review I would say this is inconclusive.")
    assert result is not None
    assert result[0] == "inconclusive"


def test_parse_challenge_output_garbage_returns_none() -> None:
    assert parse_challenge_output("") is None
    assert parse_challenge_output("I have no opinion") is None
    assert parse_challenge_output('{"result": "maybe"}') is None  # not a valid result


# --- build_challenge_prompt ---------------------------------------------------


def test_build_challenge_prompt_frames_true_positive_as_argue_fp() -> None:
    prompt = build_challenge_prompt(_verdict(verdict="true-positive"))
    assert "FALSE POSITIVE" in prompt
    assert "CWE-89" in prompt
    assert "concatenates request.args" in prompt


def test_build_challenge_prompt_frames_false_positive_as_argue_exploitable() -> None:
    prompt = build_challenge_prompt(_verdict(verdict="false-positive"))
    assert "exploitable vulnerability" in prompt


# --- make_adversarial_challenger ---------------------------------------------


def test_make_challenger_raises_when_provider_unavailable(monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    try:
        make_adversarial_challenger(LLMConfig(provider="claude"))
    except RuntimeError as exc:
        assert "not available" in str(exc)
    else:  # pragma: no cover - the call must raise
        raise AssertionError("expected RuntimeError for unavailable provider")


def _fake_run(stdout: str):
    def _run(*_args, **_kwargs):
        return SimpleNamespace(stdout=stdout, stderr="")

    return _run


def test_challenger_returns_challenge_on_success(monkeypatch) -> None:
    monkeypatch.setattr(av, "is_available", lambda _p: True)
    monkeypatch.setattr(
        av.subprocess,
        "run",
        _fake_run('{"result": "disputed", "rationale": "param is bound"}'),
    )
    challenger = make_adversarial_challenger(LLMConfig(provider="gemini"))
    challenge = challenger(_verdict(verdict="true-positive"))
    assert challenge is not None
    assert challenge.result == "disputed"
    assert challenge.challenger_provider == "gemini"
    assert challenge.original_verdict == "true-positive"
    assert challenge.disputes_a_true_positive()


def test_challenger_skips_non_decisive_verdict(monkeypatch) -> None:
    """An `inconclusive` verdict has no adversarial frame — challenger returns None."""
    monkeypatch.setattr(av, "is_available", lambda _p: True)
    monkeypatch.setattr(av.subprocess, "run", _fake_run('{"result": "confirmed"}'))
    challenger = make_adversarial_challenger(LLMConfig(provider="gemini"))
    assert challenger(_verdict(verdict="inconclusive")) is None


def test_challenger_returns_none_on_subprocess_failure(monkeypatch) -> None:
    """A broken challenger must not break the pipeline (recall-first ops)."""
    monkeypatch.setattr(av, "is_available", lambda _p: True)

    def _boom(*_args, **_kwargs):
        raise OSError("llm cli vanished")

    monkeypatch.setattr(av.subprocess, "run", _boom)
    challenger = make_adversarial_challenger(LLMConfig(provider="gemini"))
    assert challenger(_verdict()) is None


def test_challenger_returns_none_on_unparseable_output(monkeypatch) -> None:
    monkeypatch.setattr(av, "is_available", lambda _p: True)
    monkeypatch.setattr(av.subprocess, "run", _fake_run("the model rambled with no verdict word"))
    challenger = make_adversarial_challenger(LLMConfig(provider="gemini"))
    assert challenger(_verdict()) is None


# --- challenge_verdicts -------------------------------------------------------


def test_challenge_verdicts_collects_only_produced(monkeypatch) -> None:
    monkeypatch.setattr(av, "is_available", lambda _p: True)
    monkeypatch.setattr(
        av.subprocess, "run", _fake_run('{"result": "confirmed", "rationale": "x"}')
    )
    challenger = make_adversarial_challenger(LLMConfig(provider="gemini"))
    verdicts = [
        _verdict(finding_id="F-1", verdict="true-positive"),
        _verdict(finding_id="F-2", verdict="inconclusive"),  # skipped — non-decisive
        _verdict(finding_id="F-3", verdict="false-positive"),
    ]
    challenges = challenge_verdicts(verdicts, challenger=challenger)
    assert {c.finding_id for c in challenges} == {"F-1", "F-3"}


# --- persistence + load round trip -------------------------------------------


def test_persist_and_load_review_verdicts_round_trip(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    persist_review_verdicts(conn, [_verdict(finding_id="F-rt", verdict="false-positive")])
    loaded = load_review_verdicts(conn)
    assert len(loaded) == 1
    assert loaded[0].finding_id == "F-rt"
    assert loaded[0].verdict == "false-positive"
    assert loaded[0].evidence == ["src/users.py:42 concatenates request.args into SQL"]


def test_load_review_verdicts_empty_when_no_table(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "empty.duckdb"))
    assert load_review_verdicts(conn) == []


def test_persist_adversarial_challenges_is_idempotent_per_challenger(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    challenge = AdversarialChallenge(
        finding_id="F-1",
        original_verdict="true-positive",
        original_reviewer="deep_analyzer",
        challenger_provider="gemini",
        result="disputed",
        rationale="bound parameter",
    )
    persist_adversarial_challenges(conn, [challenge])
    persist_adversarial_challenges(conn, [challenge])  # re-run, same challenger
    rows = conn.execute("SELECT COUNT(*) FROM adversarial_challenges").fetchone()
    assert rows is not None
    assert rows[0] == 1
    # A different challenger stacks its own row.
    persist_adversarial_challenges(
        conn,
        [
            AdversarialChallenge(
                finding_id="F-1",
                original_verdict="true-positive",
                original_reviewer="deep_analyzer",
                challenger_provider="codex",
                result="confirmed",
                rationale="no sanitizer found",
            )
        ],
    )
    rows = conn.execute("SELECT COUNT(*) FROM adversarial_challenges").fetchone()
    assert rows is not None
    assert rows[0] == 2


# --- summary ------------------------------------------------------------------


def test_summarize_challenges_counts_disputed_false_positives() -> None:
    challenges = [
        AdversarialChallenge("F-1", "true-positive", "r", "gemini", "confirmed", ""),
        AdversarialChallenge("F-2", "true-positive", "r", "gemini", "disputed", ""),
        AdversarialChallenge("F-3", "false-positive", "r", "gemini", "disputed", ""),
        AdversarialChallenge("F-4", "false-positive", "r", "gemini", "inconclusive", ""),
    ]
    summary = summarize_challenges(challenges)
    assert summary["total"] == 4
    assert summary["confirmed"] == 1
    assert summary["disputed"] == 2
    assert summary["inconclusive"] == 1
    # The recall-critical figure: a dismissed finding a second model thinks is real.
    assert summary["disputed_false_positives"] == 1
    assert summary["disputed_true_positives"] == 1


def test_disputes_helpers_distinguish_direction() -> None:
    recall_critical = AdversarialChallenge("F", "false-positive", "r", "gemini", "disputed", "")
    assert recall_critical.disputes_a_false_positive()
    assert not recall_critical.disputes_a_true_positive()

    possible_fp = AdversarialChallenge("F", "true-positive", "r", "gemini", "disputed", "")
    assert possible_fp.disputes_a_true_positive()
    assert not possible_fp.disputes_a_false_positive()


# --- reachability -------------------------------------------------------------


def test_reachability_note_flags_colocation(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    conn.execute("CREATE TABLE flow_metadata (fid VARCHAR PRIMARY KEY, flow_type VARCHAR)")
    conn.execute("INSERT INTO flow_metadata VALUES ('flow-colo', 'co-location')")
    assert "co-location only" in reachability_note(conn, "flow-colo")
    # A flow with no metadata row defaults to data-flow proven.
    assert "data-flow proven" in reachability_note(conn, "flow-other")


def test_reachability_note_unknown_without_flow_id(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    assert "unknown" in reachability_note(conn, "")


def test_with_reachability_evidence_prepends_note(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    conn.execute("CREATE TABLE flow_metadata (fid VARCHAR PRIMARY KEY, flow_type VARCHAR)")
    conn.execute("INSERT INTO flow_metadata VALUES ('flow-1', 'co-location')")
    enriched = with_reachability_evidence(conn, [_verdict()])
    assert enriched[0].evidence[0].startswith("Reachability:")
    assert "co-location only" in enriched[0].evidence[0]
    # Original evidence is preserved after the note.
    assert "concatenates request.args" in enriched[0].evidence[1]


# --- consensus + score delta --------------------------------------------------


def test_consensus_majority_disputed() -> None:
    c = ChallengeConsensus(
        "F-1", "true-positive", challenger_count=3, confirmed=1, disputed=2, inconclusive=0
    )
    assert c.consensus == "disputed"


def test_consensus_tie_is_split() -> None:
    c = ChallengeConsensus(
        "F-1", "true-positive", challenger_count=2, confirmed=1, disputed=1, inconclusive=0
    )
    assert c.consensus == "split"


def test_consensus_no_challengers_is_none() -> None:
    c = ChallengeConsensus(
        "F-1", "true-positive", challenger_count=0, confirmed=0, disputed=0, inconclusive=0
    )
    assert c.consensus == "none"


def test_challenge_consensus_all_aggregates_per_finding(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    persist_adversarial_challenges(
        conn,
        [
            AdversarialChallenge("F-1", "true-positive", "r", "gemini", "disputed", ""),
            AdversarialChallenge("F-1", "true-positive", "r", "codex", "disputed", ""),
            AdversarialChallenge("F-1", "true-positive", "r", "claude", "confirmed", ""),
        ],
    )
    consensus = challenge_consensus_all(conn)
    assert "F-1" in consensus
    assert consensus["F-1"].challenger_count == 3
    assert consensus["F-1"].disputed == 2
    assert consensus["F-1"].consensus == "disputed"


def test_score_delta_disputed_true_positive_demotes() -> None:
    c = ChallengeConsensus("F", "true-positive", 2, confirmed=0, disputed=2, inconclusive=0)
    delta = adversarial_score_delta(c)
    assert delta is not None
    assert delta[0] == "adversarial_disputed"
    assert delta[1] < 0  # demoted


def test_score_delta_disputed_false_positive_re_elevates() -> None:
    """The recall-critical case: a dismissed finding a second model disputes
    gets a POSITIVE delta so it climbs back into review."""
    c = ChallengeConsensus("F", "false-positive", 2, confirmed=0, disputed=2, inconclusive=0)
    delta = adversarial_score_delta(c)
    assert delta is not None
    assert delta[0] == "adversarial_recall_flag"
    assert delta[1] > 0  # re-elevated


def test_score_delta_corroborated_true_positive_boosts() -> None:
    c = ChallengeConsensus("F", "true-positive", 2, confirmed=2, disputed=0, inconclusive=0)
    delta = adversarial_score_delta(c)
    assert delta is not None
    assert delta[0] == "adversarial_corroborated"
    assert delta[1] > 0


def test_score_delta_split_and_confirmed_fp_yield_nothing() -> None:
    split = ChallengeConsensus("F", "true-positive", 2, confirmed=1, disputed=1, inconclusive=0)
    assert adversarial_score_delta(split) is None
    confirmed_fp = ChallengeConsensus(
        "F", "false-positive", 2, confirmed=2, disputed=0, inconclusive=0
    )
    assert adversarial_score_delta(confirmed_fp) is None
