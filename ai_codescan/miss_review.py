"""Parsing for exploratory miss-review output and the orchestration entrypoint."""

from __future__ import annotations

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
from ai_codescan.review_verdicts import persist_miss_reviews

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


def proposal_stub_from_review(review: MissReview) -> dict[str, Any] | None:
    if review.classification not in {"new-finding", "needs-model-extension"}:
        return None
    return {
        "candidate_id": review.candidate_id,
        "classification": review.classification,
        "confidence": review.confidence,
        "rationale": review.rationale,
        "evidence": review.evidence,
        "proposal": review.proposal,
    }


def stage_miss_review_queue(
    candidates: list[dict[str, Any]],
    *,
    queue_path: Path,
    max_candidates: int,
) -> list[dict[str, Any]]:
    """Write the top ``max_candidates`` miss candidates to the review queue."""
    ranked = sorted(
        enumerate(candidates),
        key=lambda item: (
            -float(item[1].get("score") or 0.0),
            item[0],
        ),
    )
    selected = [candidate for _index, candidate in ranked[:max_candidates]]
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    with queue_path.open("w", encoding="utf-8") as f:
        for candidate in selected:
            f.write(json.dumps(candidate, sort_keys=True))
            f.write("\n")
    return selected


def ingest_miss_reviews(
    *,
    review_dir: Path,
    proposals_dir: Path,
    findings_dir: Path | None = None,
) -> list[MissReview]:
    """Read raw sentinel JSONs from ``review_dir`` and stage model proposals.

    Returns the parsed :class:`MissReview` objects in candidate-id sort order.
    Proposals (`new-finding` / `needs-model-extension`) are written under
    ``proposals_dir`` so the existing model-proposals CLI can list them.
    """
    if not review_dir.is_dir():
        return []
    reviews: list[MissReview] = []
    proposals_dir.mkdir(parents=True, exist_ok=True)
    if findings_dir:
        findings_dir.mkdir(parents=True, exist_ok=True)

    for review_file in sorted(review_dir.glob("*.json")):
        raw = review_file.read_text(encoding="utf-8", errors="replace")
        wrapped = "<<<AI_CODESCAN_MISS_REVIEW>>>\n" + raw + "\n<<<AI_CODESCAN_MISS_REVIEW:END>>>"
        review = parse_miss_review_output(wrapped)
        if review is None:
            continue
        reviews.append(review)

        # 1. Model extension proposals.
        stub = proposal_stub_from_review(review)
        if stub is not None:
            (proposals_dir / f"{review.candidate_id}.json").write_text(
                json.dumps(stub, indent=2, sort_keys=True),
                encoding="utf-8",
            )

        # 2. Findings for reporting/gating.
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

    staged = stage_miss_review_queue(
        candidates, queue_path=queue_path, max_candidates=max_candidates
    )
    effective = llm or LLMConfig(provider="claude")
    if not is_available(effective.provider):
        return {
            "queue": str(queue_path),
            "staged": len(staged),
            "executed": False,
            "reviews": 0,
        }
    cmd_script = write_llm_cmd_script(repo_dir / ".llm-cmd-miss-review.sh", effective)
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
    reviews = ingest_miss_reviews(
        review_dir=review_dir,
        proposals_dir=proposals_dir,
        findings_dir=findings_dir,
    )

    conn = duckdb.connect(str(db_path))
    routing = {"routed_to_pack": 0, "routed_to_joern": 0, "pending_custom_rule": 0}
    try:
        persist_miss_reviews(conn, reviews)
        # Phase 3 single-command flow: turn `needs-model-extension` verdicts
        # into ModelProposal artifacts, then triage each into either a
        # community-pack enablement (auto-applied) or a pending custom rule
        # (user runs `model-proposals apply` later). See
        # `ai_codescan.proposal_triage` for the mapping.
        proposals = proposals_from_verdicts(conn)
        if proposals:
            write_model_proposals(proposals, proposals_dir=proposals_dir)
            routing = triage_and_route(proposals, conn=conn, repo_dir=repo_dir)
    finally:
        conn.close()

    return {
        "queue": str(queue_path),
        "staged": len(staged),
        "executed": True,
        "reviews": len(reviews),
        "routed_to_pack": routing["routed_to_pack"],
        "routed_to_joern": routing.get("routed_to_joern", 0),
        "pending_custom_rule": routing["pending_custom_rule"],
    }
