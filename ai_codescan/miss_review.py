"""Parsing for exploratory miss-review output and the orchestration entrypoint."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, TypeGuard, get_args

import duckdb

from ai_codescan.findings.model import Finding, render_finding
from ai_codescan.llm import LLMConfig, is_available
from ai_codescan.model_proposals import proposals_from_verdicts, write_model_proposals
from ai_codescan.nominator import write_llm_cmd_script
from ai_codescan.proposal_triage import triage_and_route
from ai_codescan.review_cache import (
    ReviewCacheKey,
    build_review_cache_key,
    read_review_cache_key,
)
from ai_codescan.review_verdicts import persist_miss_reviews
from ai_codescan.scoring import select_review_candidates

SKILL_DIR = Path(__file__).resolve().parent / "skills" / "miss_reviewer"

MissReviewClassification = Literal[
    "new-finding",
    "covered-by-static",
    "false-positive",
    "needs-model-extension",
    "needs-human-context",
]

CLASSIFICATIONS: frozenset[str] = frozenset(get_args(MissReviewClassification))


def is_classification(value: str) -> TypeGuard[MissReviewClassification]:
    """Narrow an LLM-supplied string to the classification literal.

    Derived from the ``Literal`` itself, so the set can never drift from the
    type. The ``TypeGuard`` lets callers drop the value straight into
    ``MissReview`` without a cast.
    """
    return value in CLASSIFICATIONS


_REVIEW_BLOCK_RE = re.compile(
    r"<<<AI_CODESCAN_MISS_REVIEW>>>\s*(?P<body>\{.*?\})\s*<<<AI_CODESCAN_MISS_REVIEW:END>>>",
    re.DOTALL,
)


@dataclass(frozen=True, slots=True)
class MissReview:
    candidate_id: str
    classification: MissReviewClassification
    confidence: str
    rationale: str
    evidence: list[str]
    proposal: dict[str, Any]

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


def parse_miss_review_output(stdout: str) -> MissReview | None:
    match = _REVIEW_BLOCK_RE.search(stdout)
    if not match:
        return None
    try:
        data = json.loads(match.group("body"))
    except json.JSONDecodeError:
        return None
    classification = str(data.get("classification") or "")
    if not is_classification(classification):
        return None
    evidence_raw = data.get("evidence") or []
    if not isinstance(evidence_raw, list):
        evidence_raw = [str(evidence_raw)]
    proposal = data.get("proposal") or {}
    if not isinstance(proposal, dict):
        proposal = {}
    return MissReview(
        candidate_id=str(data.get("candidate_id") or ""),
        classification=classification,
        confidence=str(data.get("confidence") or ""),
        rationale=str(data.get("rationale") or ""),
        evidence=[str(item) for item in evidence_raw],
        proposal=proposal,
    )


def stage_miss_review_queue(
    candidates: list[dict[str, Any]],
    *,
    queue_path: Path,
    max_candidates: int,
) -> list[dict[str, Any]]:
    """Write a score-ranked, concern-diverse miss-review queue."""
    selected = select_review_candidates(candidates, max_candidates=max_candidates)
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    with queue_path.open("w", encoding="utf-8") as f:
        for candidate in selected:
            f.write(json.dumps(candidate, sort_keys=True))
            f.write("\n")
    return selected


def ingest_miss_reviews(
    *,
    review_dir: Path,
    findings_dir: Path | None = None,
    candidate_ids: frozenset[str] | None = None,
) -> list[MissReview]:
    """Read raw sentinel JSONs from ``review_dir``.

    Returns the parsed :class:`MissReview` objects in candidate-id sort order.
    Findings are rendered for reviews that require follow-up.
    """
    if not review_dir.is_dir():
        return []
    reviews: list[MissReview] = []
    if findings_dir:
        findings_dir.mkdir(parents=True, exist_ok=True)

    for review_file in sorted(review_dir.glob("*.json")):
        raw = review_file.read_text(encoding="utf-8", errors="replace")
        wrapped = "<<<AI_CODESCAN_MISS_REVIEW>>>\n" + raw + "\n<<<AI_CODESCAN_MISS_REVIEW:END>>>"
        review = parse_miss_review_output(wrapped)
        if review is None:
            continue
        if candidate_ids is not None and review.candidate_id not in candidate_ids:
            continue
        reviews.append(review)

        # Findings for reporting/gating.
        if findings_dir and review.classification in {"new-finding", "needs-model-extension"}:
            if review.candidate_id.startswith("B-miss-"):
                finding_id = f"F-miss-{review.candidate_id[len('B-miss-') :]}"
            else:
                finding_id = f"F-{review.candidate_id}"
            evidence_lines = "\n".join(f"- {e}" for e in review.evidence)
            finding = Finding(
                finding_id=finding_id,
                nomination_id=review.candidate_id,
                flow_id="",
                cwe=review.proposal.get("cwe"),
                status="unverified",
                title=f"Exploratory finding: {review.proposal.get('cwe', 'unknown CWE')}",
                body=f"{review.rationale}\n\nEvidence:\n{evidence_lines}",
            )
            (findings_dir / f"{finding_id}.md").write_text(
                render_finding(finding),
                encoding="utf-8",
            )

    return reviews


def _stale_candidate_ids(
    done_dir: Path,
    review_dir: Path,
    candidate_cache_keys: dict[str, ReviewCacheKey],
) -> frozenset[str]:
    stale_candidate_ids: set[str] = set()
    for candidate_id, cache_key in candidate_cache_keys.items():
        marker = done_dir / candidate_id
        review_path = review_dir / f"{candidate_id}.json"
        if not marker.is_file() or not review_path.is_file():
            stale_candidate_ids.add(candidate_id)
            continue
        try:
            raw = review_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            stale_candidate_ids.add(candidate_id)
            continue
        if read_review_cache_key(marker) != cache_key:
            stale_candidate_ids.add(candidate_id)
            continue
        wrapped = f"<<<AI_CODESCAN_MISS_REVIEW>>>\n{raw}\n<<<AI_CODESCAN_MISS_REVIEW:END>>>"
        review = parse_miss_review_output(wrapped)
        if review is None or review.candidate_id != candidate_id:
            stale_candidate_ids.add(candidate_id)
    return frozenset(stale_candidate_ids)


def _is_obsolete_candidate(
    candidate_id: str,
    *,
    current_candidate_ids: frozenset[str],
    stale_candidate_ids: frozenset[str],
) -> bool:
    return candidate_id not in current_candidate_ids or candidate_id in stale_candidate_ids


def _remove_obsolete_proposals(
    proposals_dir: Path,
    *,
    current_candidate_ids: frozenset[str],
    stale_candidate_ids: frozenset[str],
) -> None:
    for proposal_path in proposals_dir.glob("*.json"):
        candidate_id = proposal_path.stem if proposal_path.stem.startswith("B-miss-") else ""
        if candidate_id and _is_obsolete_candidate(
            candidate_id,
            current_candidate_ids=current_candidate_ids,
            stale_candidate_ids=stale_candidate_ids,
        ):
            proposal_path.unlink(missing_ok=True)
            continue
        try:
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            if proposal_path.name.startswith("proposal-"):
                proposal_path.unlink(missing_ok=True)
            continue
        if not isinstance(proposal, dict):
            continue
        candidate_id = str(proposal.get("candidate_id") or proposal.get("nomination_id") or "")
        if candidate_id.startswith("B-miss-") and _is_obsolete_candidate(
            candidate_id,
            current_candidate_ids=current_candidate_ids,
            stale_candidate_ids=stale_candidate_ids,
        ):
            proposal_path.unlink(missing_ok=True)


def _remove_obsolete_miss_artifacts(
    *,
    repo_dir: Path,
    run_dir: Path,
    candidate_cache_keys: dict[str, ReviewCacheKey],
) -> None:
    """Remove generated artifacts that cannot describe the current queue."""
    current_candidate_ids = frozenset(candidate_cache_keys)
    done_dir = repo_dir / ".done-miss-review"
    review_dir = repo_dir / "miss_reviews"
    stale_candidate_ids = _stale_candidate_ids(
        done_dir,
        review_dir,
        candidate_cache_keys,
    )
    for review_path in review_dir.glob("B-miss-*.json"):
        if _is_obsolete_candidate(
            review_path.stem,
            current_candidate_ids=current_candidate_ids,
            stale_candidate_ids=stale_candidate_ids,
        ):
            review_path.unlink(missing_ok=True)

    for done_path in done_dir.glob("B-miss-*"):
        candidate_id = done_path.name.removesuffix(".stdout")
        if _is_obsolete_candidate(
            candidate_id,
            current_candidate_ids=current_candidate_ids,
            stale_candidate_ids=stale_candidate_ids,
        ):
            done_path.unlink(missing_ok=True)

    findings_dir = run_dir / "findings"
    for finding_path in findings_dir.glob("F-miss-*.md"):
        candidate_id = f"B-miss-{finding_path.stem.removeprefix('F-miss-')}"
        if _is_obsolete_candidate(
            candidate_id,
            current_candidate_ids=current_candidate_ids,
            stale_candidate_ids=stale_candidate_ids,
        ):
            finding_path.unlink(missing_ok=True)

    _remove_obsolete_proposals(
        run_dir / "model_proposals",
        current_candidate_ids=current_candidate_ids,
        stale_candidate_ids=stale_candidate_ids,
    )


def _remove_outputs_for_candidates(
    *,
    findings_dir: Path,
    proposals_dir: Path,
    candidate_ids: frozenset[str],
) -> None:
    """Clear derived outputs before recreating them from current reviews."""
    for candidate_id in candidate_ids:
        finding_id = candidate_id.removeprefix("B-miss-")
        (findings_dir / f"F-miss-{finding_id}.md").unlink(missing_ok=True)
    for proposal_path in proposals_dir.glob("*.json"):
        if proposal_path.stem in candidate_ids:
            proposal_path.unlink(missing_ok=True)
            continue
        try:
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(proposal, dict):
            continue
        source_id = str(proposal.get("candidate_id") or proposal.get("nomination_id") or "")
        if source_id in candidate_ids:
            proposal_path.unlink(missing_ok=True)


def _candidate_evidence_fingerprint(candidate: dict[str, Any], *, repo_dir: Path) -> str:
    """Return the fingerprint of the prompt and evidence, excluding the LLM."""
    stored = str(
        candidate.get("review_evidence_fingerprint") or candidate.get("review_fingerprint") or ""
    )
    if stored:
        return stored
    candidate_bytes = json.dumps(candidate, sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(candidate_bytes)
    bundle_value = str(candidate.get("bundle_json") or "")
    bundle_path = (
        Path(bundle_value)
        if bundle_value
        else repo_dir / "miss_bundles" / (f"{candidate.get('id', '')}.json")
    )
    if bundle_path.is_file():
        digest.update(bundle_path.read_bytes())
    return digest.hexdigest()


def _bind_review_cache_keys(
    candidates: list[dict[str, Any]],
    *,
    repo_dir: Path,
    llm: LLMConfig,
) -> tuple[list[dict[str, Any]], dict[str, ReviewCacheKey]]:
    bound: list[dict[str, Any]] = []
    cache_keys: dict[str, ReviewCacheKey] = {}
    for candidate in candidates:
        candidate_id = str(candidate.get("id") or "")
        evidence_fingerprint = _candidate_evidence_fingerprint(candidate, repo_dir=repo_dir)
        cache_key = build_review_cache_key(evidence_fingerprint, llm)
        if candidate_id:
            cache_keys[candidate_id] = cache_key
        bound.append(
            {
                **candidate,
                "review_evidence_fingerprint": cache_key.evidence_fingerprint,
                "review_fingerprint": cache_key.review_fingerprint,
                "review_model": cache_key.model,
                "review_provider": cache_key.provider,
            }
        )
    return bound, cache_keys


def _execute_review_loop(
    *,
    repo_dir: Path,
    queue_path: Path,
    review_dir: Path,
    llm: LLMConfig,
) -> None:
    cmd_script = write_llm_cmd_script(repo_dir / ".llm-cmd-miss-review.sh", llm)
    env = os.environ.copy()
    env["AI_CODESCAN_RUN_DIR"] = str(repo_dir)
    env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
    env["AI_CODESCAN_LLM_CMD"] = str(cmd_script)
    env["AI_CODESCAN_SOURCE_ROOT"] = str(repo_dir / "source")
    env["AI_CODESCAN_MISS_QUEUE"] = str(queue_path)
    env["AI_CODESCAN_MISS_REVIEW_DIR"] = str(review_dir)
    env["AI_CODESCAN_MISS_BUNDLES_DIR"] = str(repo_dir / "miss_bundles")
    env["CLAUDE_NO_AUTO_REGISTER"] = "1"
    subprocess.run(  # noqa: S603 - argv-only, no shell
        ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
        env=env,
        check=True,
    )


def _require_complete_reviews(
    *,
    repo_dir: Path,
    review_dir: Path,
    staged_candidate_ids: frozenset[str],
    candidate_cache_keys: dict[str, ReviewCacheKey],
) -> None:
    staged_cache_keys = {
        candidate_id: candidate_cache_keys[candidate_id]
        for candidate_id in staged_candidate_ids
        if candidate_id in candidate_cache_keys
    }
    incomplete = _stale_candidate_ids(
        repo_dir / ".done-miss-review",
        review_dir,
        staged_cache_keys,
    )
    if incomplete:
        missing = ", ".join(sorted(incomplete))
        raise RuntimeError(f"miss-review loop completed without valid reviews for: {missing}")


def _persist_reviews_and_route(
    *,
    db_path: Path,
    reviews: list[MissReview],
    proposals_dir: Path,
    repo_dir: Path,
) -> dict[str, int]:
    routing = {"routed_to_pack": 0, "routed_to_joern": 0, "pending_custom_rule": 0}
    conn = duckdb.connect(str(db_path))
    try:
        persist_miss_reviews(conn, reviews)
        reviewed_candidate_ids = frozenset(review.candidate_id for review in reviews)
        proposals = proposals_from_verdicts(
            conn,
            nomination_ids=reviewed_candidate_ids,
            proposal_details={review.candidate_id: review.proposal for review in reviews},
        )
        if proposals:
            write_model_proposals(proposals, proposals_dir=proposals_dir)
            routing = triage_and_route(proposals, conn=conn, repo_dir=repo_dir)
    finally:
        conn.close()
    return routing


def run_miss_review(  # noqa: PLR0913 - keyword-only fan-in mirrors run_analyzer's shape
    *,
    candidates_path: Path,
    repo_dir: Path,
    db_path: Path,
    run_dir: Path,
    max_candidates: int = 20,
    llm: LLMConfig | None = None,
) -> dict[str, Any]:
    """Stage the queue and, when an LLM CLI is on PATH, execute the loop.

    Returns a small dict describing what happened: ``{"queue": <path>,
    "executed": <bool>, "reviews": <int>}``. The caller (CLI) decides what to
    print to the user.
    """
    if not candidates_path.is_file():
        raise FileNotFoundError(f"no miss_candidates.jsonl at {candidates_path}")
    candidates = [
        json.loads(line)
        for line in candidates_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    queue_path = repo_dir / "miss_review_queue.jsonl"
    review_dir = repo_dir / "miss_reviews"
    proposals_dir = run_dir / "model_proposals"
    findings_dir = run_dir / "findings"
    effective = llm or LLMConfig(provider="claude")
    candidates, candidate_cache_keys = _bind_review_cache_keys(
        candidates,
        repo_dir=repo_dir,
        llm=effective,
    )

    staged = stage_miss_review_queue(
        candidates, queue_path=queue_path, max_candidates=max_candidates
    )
    _remove_obsolete_miss_artifacts(
        repo_dir=repo_dir,
        run_dir=run_dir,
        candidate_cache_keys=candidate_cache_keys,
    )
    if not is_available(effective.provider):
        return {
            "queue": str(queue_path),
            "staged": len(staged),
            "executed": False,
            "reviews": 0,
        }
    _execute_review_loop(
        repo_dir=repo_dir,
        queue_path=queue_path,
        review_dir=review_dir,
        llm=effective,
    )
    staged_candidate_ids = frozenset(
        candidate_id for candidate in staged if (candidate_id := str(candidate.get("id") or ""))
    )
    _require_complete_reviews(
        repo_dir=repo_dir,
        review_dir=review_dir,
        staged_candidate_ids=staged_candidate_ids,
        candidate_cache_keys=candidate_cache_keys,
    )
    _remove_outputs_for_candidates(
        findings_dir=findings_dir,
        proposals_dir=proposals_dir,
        candidate_ids=staged_candidate_ids,
    )
    reviews = ingest_miss_reviews(
        review_dir=review_dir,
        findings_dir=findings_dir,
        candidate_ids=staged_candidate_ids,
    )
    routing = _persist_reviews_and_route(
        db_path=db_path,
        reviews=reviews,
        proposals_dir=proposals_dir,
        repo_dir=repo_dir,
    )

    return {
        "queue": str(queue_path),
        "staged": len(staged),
        "executed": True,
        "reviews": len(reviews),
        "routed_to_pack": routing["routed_to_pack"],
        "routed_to_joern": routing.get("routed_to_joern", 0),
        "pending_custom_rule": routing["pending_custom_rule"],
    }
