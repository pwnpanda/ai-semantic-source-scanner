"""Persistence for structured bundle-review verdicts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb
import yaml

VERDICTS = {
    "true-positive",
    "false-positive",
    "inconclusive",
    "needs-model-extension",
}


@dataclass(frozen=True, slots=True)
class ReviewVerdict:
    nomination_id: str
    finding_id: str
    flow_id: str
    candidate_id: str
    verdict: str
    status: str
    confidence: str
    cwe: str
    title: str
    evidence: list[str]
    reviewer: str
    source_path: str


def _frontmatter(md: str) -> dict[str, Any]:
    if not md.startswith("---\n"):
        return {}
    end = md.find("\n---\n", 4)
    if end == -1:
        return {}
    data = yaml.safe_load(md[4:end]) or {}
    return data if isinstance(data, dict) else {}


def _fallback_verdict(status: str) -> str:
    if status == "rejected":
        return "false-positive"
    if status == "verified":
        return "true-positive"
    return "inconclusive"


def parse_review_verdict(path: Path, *, reviewer: str = "deep_analyzer") -> ReviewVerdict | None:
    """Parse structured review metadata from a finding markdown file."""
    front = _frontmatter(path.read_text(encoding="utf-8"))
    if not front:
        return None
    status = str(front.get("status") or "")
    verdict = str(front.get("analysis_verdict") or "").strip().lower()
    if verdict not in VERDICTS:
        verdict = _fallback_verdict(status)
    evidence_raw = front.get("evidence") or front.get("evidence_refs") or []
    if not isinstance(evidence_raw, list):
        evidence_raw = [str(evidence_raw)]
    finding_id = str(front.get("finding_id") or path.stem)
    nomination_id = str(front.get("nomination_id") or "")
    if not nomination_id and finding_id.startswith("F-"):
        nomination_id = f"N-{finding_id[2:]}"
    return ReviewVerdict(
        nomination_id=nomination_id,
        finding_id=finding_id,
        flow_id=str(front.get("flow_id") or ""),
        candidate_id=str(front.get("candidate_id") or nomination_id),
        verdict=verdict,
        status=status,
        confidence=str(front.get("confidence") or ""),
        cwe=str(front.get("cwe") or ""),
        title=str(front.get("title") or ""),
        evidence=[str(item) for item in evidence_raw],
        reviewer=reviewer,
        source_path=str(path),
    )


def persist_review_verdicts(
    conn: duckdb.DuckDBPyConnection,
    verdicts: list[ReviewVerdict],
) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS review_verdicts (
          nomination_id VARCHAR PRIMARY KEY,
          finding_id VARCHAR,
          flow_id VARCHAR,
          candidate_id VARCHAR,
          verdict VARCHAR,
          status VARCHAR,
          confidence VARCHAR,
          cwe VARCHAR,
          title VARCHAR,
          evidence_json VARCHAR,
          reviewer VARCHAR,
          source_path VARCHAR,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    for verdict in verdicts:
        conn.execute(
            """
            INSERT OR REPLACE INTO review_verdicts
              (
                nomination_id, finding_id, flow_id, candidate_id, verdict, status,
                confidence, cwe, title, evidence_json, reviewer, source_path
              )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                verdict.nomination_id,
                verdict.finding_id,
                verdict.flow_id,
                verdict.candidate_id,
                verdict.verdict,
                verdict.status,
                verdict.confidence,
                verdict.cwe,
                verdict.title,
                json.dumps(verdict.evidence, sort_keys=True),
                verdict.reviewer,
                verdict.source_path,
            ],
        )


def persist_miss_reviews(
    conn: duckdb.DuckDBPyConnection,
    reviews: list[Any],  # list[MissReview]
    *,
    reviewer: str = "miss_reviewer",
) -> None:
    """Sync exploratory miss-reviews into the shared review_verdicts table."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS review_verdicts (
          nomination_id VARCHAR PRIMARY KEY,
          finding_id VARCHAR,
          flow_id VARCHAR,
          candidate_id VARCHAR,
          verdict VARCHAR,
          status VARCHAR,
          confidence VARCHAR,
          cwe VARCHAR,
          title VARCHAR,
          evidence_json VARCHAR,
          reviewer VARCHAR,
          source_path VARCHAR,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    for review in reviews:
        # Miss reviews use candidate_id as the primary key since they lack
        # deterministic nominations.
        conn.execute(
            """
            INSERT OR REPLACE INTO review_verdicts
              (
                nomination_id, finding_id, flow_id, candidate_id, verdict, status,
                confidence, cwe, title, evidence_json, reviewer, source_path
              )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                review.candidate_id,  # nomination_id fallback
                review.candidate_id,  # finding_id fallback
                "",  # flow_id
                review.candidate_id,
                review.classification,
                "verified" if review.classification == "new-finding" else "rejected",
                review.confidence,
                review.proposal.get("cwe", ""),
                review.rationale,
                json.dumps(review.evidence, sort_keys=True),
                reviewer,
                "",  # source_path
            ],
        )


def sync_review_verdicts(
    conn: duckdb.DuckDBPyConnection,
    findings_dir: Path,
    *,
    reviewer: str = "deep_analyzer",
) -> list[ReviewVerdict]:
    if not findings_dir.is_dir():
        return []
    verdicts = [
        verdict
        for path in sorted(findings_dir.glob("*.md"))
        if (verdict := parse_review_verdict(path, reviewer=reviewer)) is not None
    ]
    persist_review_verdicts(conn, verdicts)
    return verdicts
