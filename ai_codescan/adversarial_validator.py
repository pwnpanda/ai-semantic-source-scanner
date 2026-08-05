"""Adversarial cross-model validation of review verdicts (Phase 13).

Modelled on the validation pillar of `evilsocket/audit`: a finding is only
trustworthy once a *second, independent model* has tried — and failed — to
disprove it. A single reviewer's verdict is treated as an unreliable signal.

The challenger runs against an existing `review_verdicts` row and is told
to argue *against* the original verdict:

- original ``true-positive``  → challenger argues it is a false positive.
- original ``false-positive`` → challenger argues it is actually exploitable.

The challenge result is uniform regardless of direction:

- ``confirmed``    — the challenger agrees with the original verdict.
- ``disputed``     — the challenger disagrees (found a counter-argument).
- ``inconclusive`` — the challenger could not decide.

Recall-first reconciliation (this is where ai-codescan diverges from audit):
audit *drops* findings that fail validation. ai-codescan's Recall-First
Invariants forbid silent drops, so a challenge never deletes anything — it
records an `adversarial_challenges` row. The two disputed cases are handled
asymmetrically by severity, not by suppression:

- A disputed ``true-positive`` is a possible false positive — worth a
  reviewer's second look, but the finding stays visible.
- A disputed ``false-positive`` is a possible *missed* vulnerability — the
  recall-critical case. The CLI surfaces these loudly.

Only decisive verdicts (``true-positive`` / ``false-positive``) are
challenged; challenging an ``inconclusive`` verdict has no adversarial frame.

The challenger should be a *different provider* than the one that produced
the original review — that independence is the whole point. The caller
picks the provider; `challenge_verdicts` does not enforce it (the
`review_verdicts` table records the reviewer skill, not its LLM provider),
but the CLI defaults the challenger to a non-default provider.
"""

from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Any

import duckdb

from ai_codescan.llm import LLMConfig, build_argv, is_available
from ai_codescan.review_verdicts import ReviewVerdict

log = logging.getLogger(__name__)

CHALLENGE_RESULTS = {"confirmed", "disputed", "inconclusive"}
"""The three uniform challenge outcomes (see module docstring)."""

# Only decisive verdicts get challenged — an adversarial prompt needs a
# concrete claim to argue against.
CHALLENGEABLE_VERDICTS = {"true-positive", "false-positive"}

_PROMPT_TEMPLATE = """\
You are an independent security reviewer performing adversarial validation.
A prior reviewer reached a verdict on a candidate finding. Your job is to
challenge that verdict — argue the opposite case as hard as the evidence
allows, then report whether the original verdict survives your challenge.

Original verdict: {original_verdict}
Your task: {task}

CWE:   {cwe}
Title: {title}

Evidence the original reviewer cited:
{evidence}

Decide one of:
  confirmed    — you could NOT disprove the original verdict; it stands.
  disputed     — you found a concrete counter-argument; the verdict is wrong.
  inconclusive — the evidence is insufficient to decide either way.

Output ONLY a JSON object, no markdown fences, no commentary:
{{"result": "confirmed|disputed|inconclusive", "rationale": "one or two sentences"}}"""

_TASK_BY_VERDICT = {
    "true-positive": (
        "The reviewer called this an exploitable vulnerability. Argue why it "
        "is a FALSE POSITIVE — a missing sanitizer you overlooked, an "
        "unreachable path, a framework default that already neutralises it. "
        "If you genuinely cannot, the result is 'confirmed'."
    ),
    "false-positive": (
        "The reviewer dismissed this as a false positive. Argue why it MIGHT "
        "be a real, exploitable vulnerability — an attacker-controlled path "
        "the reviewer missed, a sanitizer that does not actually apply. If "
        "you genuinely cannot find an attack path, the result is 'confirmed'."
    ),
}


@dataclass(frozen=True, slots=True)
class AdversarialChallenge:
    """One challenger's verdict on one prior review verdict."""

    finding_id: str
    original_verdict: str
    original_reviewer: str
    challenger_provider: str
    result: str  # one of CHALLENGE_RESULTS
    rationale: str

    def disputes_a_false_positive(self) -> bool:
        """True when the challenger thinks a dismissed finding is real.

        This is the recall-critical case — a potential missed vulnerability.
        """
        return self.original_verdict == "false-positive" and self.result == "disputed"

    def disputes_a_true_positive(self) -> bool:
        """True when the challenger thinks a reported finding is a false positive."""
        return self.original_verdict == "true-positive" and self.result == "disputed"


def parse_challenge_output(raw: str) -> tuple[str, str] | None:
    """Extract ``(result, rationale)`` from the challenger's stdout.

    Schema-driven first: the prompt asks for a JSON object, so we look for
    the first ``{...}`` span and parse it. If that fails, fall back to a
    token scan for a bare result word. Returns None when nothing parses.
    """
    if not raw:
        return None
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end > start:
        try:
            payload = json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            result = str(payload.get("result") or "").strip().lower()
            if result in CHALLENGE_RESULTS:
                return result, str(payload.get("rationale") or "").strip()
    # Fallback: a model that ignored the JSON instruction still usually
    # emits one of the result words somewhere in its prose.
    for token in raw.replace("\n", " ").split():
        clean = token.strip(",.;:!?\"'`*").lower()
        if clean in CHALLENGE_RESULTS:
            return clean, raw.strip()[:300]
    return None


def build_challenge_prompt(verdict: ReviewVerdict) -> str:
    """Render the adversarial prompt for one review verdict."""
    evidence = "\n".join(f"- {item}" for item in verdict.evidence) or "(none cited)"
    return _PROMPT_TEMPLATE.format(
        original_verdict=verdict.verdict,
        task=_TASK_BY_VERDICT.get(verdict.verdict, ""),
        cwe=verdict.cwe or "unknown",
        title=verdict.title or "(untitled)",
        evidence=evidence,
    )


def make_adversarial_challenger(
    llm: LLMConfig,
    *,
    timeout_seconds: int = 180,
) -> Callable[[ReviewVerdict], AdversarialChallenge | None]:
    """Return a callable that challenges one `ReviewVerdict` via `llm`.

    Construction raises ``RuntimeError`` when the provider isn't on PATH so
    the caller can fall back to "skip adversarial validation". The returned
    callable never raises — a failed LLM call logs and returns None, and
    the verdict is simply left unchallenged (recall-first ops: a broken
    challenger must not break the pipeline).
    """
    if not is_available(llm.provider):
        msg = f"llm provider '{llm.provider}' is not available on PATH"
        raise RuntimeError(msg)

    def _challenge(verdict: ReviewVerdict) -> AdversarialChallenge | None:
        if verdict.verdict not in CHALLENGEABLE_VERDICTS:
            return None
        prompt = build_challenge_prompt(verdict)
        argv = build_argv(llm, prompt)
        try:
            result = subprocess.run(  # noqa: S603 - argv-only, no shell
                argv,  # noqa: S607
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
                text=True,
            )
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as exc:
            log.warning("adversarial challenger LLM call failed: %s", exc)
            return None
        parsed = parse_challenge_output(result.stdout)
        if parsed is None:
            log.warning(
                "adversarial challenger produced unparseable output for %s",
                verdict.finding_id,
            )
            return None
        challenge_result, rationale = parsed
        return AdversarialChallenge(
            finding_id=verdict.finding_id,
            original_verdict=verdict.verdict,
            original_reviewer=verdict.reviewer,
            challenger_provider=llm.provider,
            result=challenge_result,
            rationale=rationale,
        )

    return _challenge


def challenge_verdicts(
    verdicts: Iterable[ReviewVerdict],
    *,
    challenger: Callable[[ReviewVerdict], AdversarialChallenge | None],
) -> list[AdversarialChallenge]:
    """Run `challenger` over every decisive verdict; collect the challenges.

    Verdicts the challenger skips (non-decisive) or fails on (LLM error)
    simply produce no row — they are left unchallenged, never dropped.
    """
    challenges: list[AdversarialChallenge] = []
    for verdict in verdicts:
        challenge = challenger(verdict)
        if challenge is not None:
            challenges.append(challenge)
    return challenges


def reachability_note(conn: duckdb.DuckDBPyConnection, flow_id: str) -> str:
    """Human reachability note for a flow, for the adversarial prompt.

    audit pillar #5 — a finding is only as strong as the proof that
    attacker input reaches the sink. ai-codescan already records this in
    `flow_metadata.flow_type`: a ``co-location`` flow is proximity only,
    not a proven data-flow path. Surfacing it to the challenger sharpens
    the adversarial argument (recall-first: it informs, it does not drop).
    """
    if not flow_id:
        return "unknown — this finding has no traced data-flow path"
    has_table = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'flow_metadata'"
    ).fetchone()
    if has_table and int(has_table[0]) > 0:
        row = conn.execute(
            "SELECT flow_type FROM flow_metadata WHERE fid = ?", [flow_id]
        ).fetchone()
        if row is not None and str(row[0]) == "co-location":
            return (
                "co-location only — the sink is near the source but NO data-flow "
                "path was proven; reachability is unverified"
            )
    return "data-flow proven — a traced path links the source to the sink"


def with_reachability_evidence(
    conn: duckdb.DuckDBPyConnection,
    verdicts: Iterable[ReviewVerdict],
) -> list[ReviewVerdict]:
    """Prepend a reachability note to each verdict's evidence list.

    Non-destructive — returns new `ReviewVerdict` objects (the dataclass is
    frozen). The note flows into `build_challenge_prompt` via the evidence
    block, so the challenger argues with reachability in hand.
    """
    enriched: list[ReviewVerdict] = []
    for verdict in verdicts:
        note = f"Reachability: {reachability_note(conn, verdict.flow_id)}"
        enriched.append(replace(verdict, evidence=[note, *verdict.evidence]))
    return enriched


def load_review_verdicts(conn: duckdb.DuckDBPyConnection) -> list[ReviewVerdict]:
    """Read every persisted review verdict back out of `review_verdicts`."""
    has_table = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'review_verdicts'"
    ).fetchone()
    if not has_table or int(has_table[0]) == 0:
        return []
    rows = conn.execute(
        """
        SELECT nomination_id, finding_id, flow_id, candidate_id, verdict, status,
               confidence, cwe, title, evidence_json, reviewer, source_path
        FROM review_verdicts
        """
    ).fetchall()
    verdicts: list[ReviewVerdict] = []
    for row in rows:
        try:
            evidence = json.loads(row[9]) if row[9] else []
        except json.JSONDecodeError:
            evidence = []
        verdicts.append(
            ReviewVerdict(
                nomination_id=str(row[0] or ""),
                finding_id=str(row[1] or ""),
                flow_id=str(row[2] or ""),
                candidate_id=str(row[3] or ""),
                verdict=str(row[4] or ""),
                status=str(row[5] or ""),
                confidence=str(row[6] or ""),
                cwe=str(row[7] or ""),
                title=str(row[8] or ""),
                evidence=[str(item) for item in evidence],
                reviewer=str(row[10] or ""),
                source_path=str(row[11] or ""),
            )
        )
    return verdicts


def persist_adversarial_challenges(
    conn: duckdb.DuckDBPyConnection,
    challenges: Iterable[AdversarialChallenge],
) -> None:
    """Write challenges to the `adversarial_challenges` table.

    Primary key is ``(finding_id, challenger_provider)`` — re-running with
    the same challenger replaces its row, but a second challenger adds its
    own (audit allows stacking independent challengers).
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS adversarial_challenges (
          finding_id VARCHAR,
          original_verdict VARCHAR,
          original_reviewer VARCHAR,
          challenger_provider VARCHAR,
          result VARCHAR,
          rationale VARCHAR,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (finding_id, challenger_provider)
        )
        """
    )
    for challenge in challenges:
        conn.execute(
            """
            INSERT OR REPLACE INTO adversarial_challenges
              (finding_id, original_verdict, original_reviewer,
               challenger_provider, result, rationale)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                challenge.finding_id,
                challenge.original_verdict,
                challenge.original_reviewer,
                challenge.challenger_provider,
                challenge.result,
                challenge.rationale,
            ],
        )


@dataclass(frozen=True, slots=True)
class ChallengeConsensus:
    """Aggregate of every challenger's verdict on one finding.

    audit allows stacking independent challengers; this collapses the
    `adversarial_challenges` rows for one finding into a single signal.
    """

    finding_id: str
    original_verdict: str
    challenger_count: int
    confirmed: int
    disputed: int
    inconclusive: int

    @property
    def consensus(self) -> str:
        """``confirmed`` | ``disputed`` | ``split`` | ``none``.

        A simple majority of decisive votes wins; an equal split (or no
        challengers) yields ``split`` / ``none`` — no actionable signal.
        """
        if self.challenger_count == 0:
            return "none"
        if self.disputed > self.confirmed:
            return "disputed"
        if self.confirmed > self.disputed:
            return "confirmed"
        return "split"


def challenge_consensus_all(conn: duckdb.DuckDBPyConnection) -> dict[str, ChallengeConsensus]:
    """Aggregate `adversarial_challenges` into one consensus per finding."""
    has_table = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'adversarial_challenges'"
    ).fetchone()
    if not has_table or int(has_table[0]) == 0:
        return {}
    rows = conn.execute(
        """
        SELECT finding_id,
               ANY_VALUE(original_verdict),
               COUNT(*),
               SUM(CASE WHEN result = 'confirmed' THEN 1 ELSE 0 END),
               SUM(CASE WHEN result = 'disputed' THEN 1 ELSE 0 END),
               SUM(CASE WHEN result = 'inconclusive' THEN 1 ELSE 0 END)
        FROM adversarial_challenges
        GROUP BY finding_id
        """
    ).fetchall()
    return {
        str(row[0]): ChallengeConsensus(
            finding_id=str(row[0]),
            original_verdict=str(row[1] or ""),
            challenger_count=int(row[2] or 0),
            confirmed=int(row[3] or 0),
            disputed=int(row[4] or 0),
            inconclusive=int(row[5] or 0),
        )
        for row in rows
    }


def adversarial_score_delta(consensus: ChallengeConsensus) -> tuple[str, float, str] | None:
    """Return ``(factor_name, score_delta, reason)`` for a consensus, or None.

    Recall-first asymmetry — this is the crux of the audit reconciliation:

    - A disputed *true-positive* is demoted (a possible false positive) but
      stays visible.
    - A disputed *false-positive* is RE-ELEVATED (`+0.3`) — a second model
      thinks a dismissed finding is real, which is exactly the false
      negative recall-first exists to catch.
    - A corroborated true-positive gets a small boost.
    - A confirmed false-positive yields no delta (a second model agreed it
      is safe — fine, leave the ranking alone).
    """
    verdict = consensus.consensus
    if verdict in {"none", "split"}:
        return None
    n = consensus.challenger_count
    if consensus.original_verdict == "true-positive":
        if verdict == "disputed":
            return (
                "adversarial_disputed",
                -0.2,
                f"{consensus.disputed}/{n} independent challenger(s) dispute this "
                "reported finding — possible false positive, verify before reporting",
            )
        return (
            "adversarial_corroborated",
            0.1,
            f"{consensus.confirmed}/{n} independent challenger(s) could not disprove this finding",
        )
    if consensus.original_verdict == "false-positive" and verdict == "disputed":
        return (
            "adversarial_recall_flag",
            0.3,
            f"{consensus.disputed}/{n} independent challenger(s) think this DISMISSED "
            "finding is actually exploitable — re-review for a possible missed bug",
        )
    return None


def summarize_challenges(challenges: list[AdversarialChallenge]) -> dict[str, Any]:
    """Counts for the CLI summary.

    ``disputed_false_positives`` is the recall-critical figure — verdicts a
    reviewer dismissed that a second model thinks are real.
    """
    return {
        "total": len(challenges),
        "confirmed": sum(1 for c in challenges if c.result == "confirmed"),
        "disputed": sum(1 for c in challenges if c.result == "disputed"),
        "inconclusive": sum(1 for c in challenges if c.result == "inconclusive"),
        "disputed_true_positives": sum(1 for c in challenges if c.disputes_a_true_positive()),
        "disputed_false_positives": sum(1 for c in challenges if c.disputes_a_false_positive()),
    }
