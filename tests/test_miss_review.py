"""Tests for exploratory miss-review parsing and orchestration."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
import pytest

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.llm import LLMConfig
from ai_codescan.miss_review import (
    ingest_miss_reviews,
    parse_miss_review_output,
    proposal_stub_from_review,
    run_miss_review,
)


def test_parse_miss_review_output_extracts_classification() -> None:
    parsed = parse_miss_review_output(
        """
noise
<<<AI_CODESCAN_MISS_REVIEW>>>
{
  "candidate_id": "B-miss-0001",
  "classification": "needs-model-extension",
  "confidence": "medium",
  "rationale": "owner check is missing",
  "evidence": ["Program.cs:12"],
  "proposal": {"cwe": "CWE-639", "target_engine": "heuristic"}
}
<<<AI_CODESCAN_MISS_REVIEW:END>>>
"""
    )

    assert parsed is not None
    assert parsed.candidate_id == "B-miss-0001"
    assert parsed.classification == "needs-model-extension"
    assert parsed.evidence == ["Program.cs:12"]


def test_parse_miss_review_output_rejects_unknown_classification() -> None:
    parsed = parse_miss_review_output(
        """
<<<AI_CODESCAN_MISS_REVIEW>>>
{"candidate_id":"x","classification":"maybe"}
<<<AI_CODESCAN_MISS_REVIEW:END>>>
"""
    )

    assert parsed is None


def test_proposal_stub_only_for_new_findings_and_model_gaps() -> None:
    review = parse_miss_review_output(
        """
<<<AI_CODESCAN_MISS_REVIEW>>>
{"candidate_id":"x","classification":"new-finding","evidence":["a:1"]}
<<<AI_CODESCAN_MISS_REVIEW:END>>>
"""
    )

    assert review is not None
    assert proposal_stub_from_review(review) is not None


def _write_candidates(repo_dir: Path) -> Path:
    repo_dir.mkdir(parents=True, exist_ok=True)
    candidates_path = repo_dir / "miss_candidates.jsonl"
    candidates_path.write_text(
        json.dumps(
            {
                "id": "B-miss-0001",
                "stream": "B",
                "vector": "authz/bola",
                "cwe": "CWE-639",
                "file": "/tmp/server.js",
                "line": 5,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return candidates_path


def test_run_miss_review_stages_queue_when_llm_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§16: when no LLM CLI is on PATH, the queue is staged and the loop is skipped."""
    monkeypatch.setenv("PATH", "/nonexistent")
    repo_dir = tmp_path / "repo"
    candidates_path = _write_candidates(repo_dir)

    db_path = repo_dir / "index.duckdb"
    run_dir = repo_dir / "runs" / "test"
    result = run_miss_review(
        candidates_path=candidates_path,
        repo_dir=repo_dir,
        db_path=db_path,
        run_dir=run_dir,
        max_candidates=10,
        llm=LLMConfig(provider="claude"),
    )

    assert result["executed"] is False
    assert result["staged"] == 1
    queue_path = repo_dir / "miss_review_queue.jsonl"
    assert queue_path.is_file()
    assert "B-miss-0001" in queue_path.read_text(encoding="utf-8")


def test_run_miss_review_invokes_loop_when_llm_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§16: when the LLM CLI exists, the loop subprocess is invoked, and any
    review JSONs it produces are ingested as model proposals."""
    repo_dir = tmp_path / "repo"
    candidates_path = _write_candidates(repo_dir)
    review_dir = repo_dir / "miss_reviews"

    def fake_subprocess_run(argv: list[str], *, env: dict[str, str], check: bool) -> None:
        # Simulate the loop writing a review JSON.
        review_dir.mkdir(parents=True, exist_ok=True)
        (review_dir / "B-miss-0001.json").write_text(
            json.dumps(
                {
                    "candidate_id": "B-miss-0001",
                    "classification": "new-finding",
                    "confidence": "medium",
                    "rationale": "no owner check on resource-id route",
                    "evidence": ["/tmp/server.js:5"],
                    "proposal": {"cwe": "CWE-639", "target_engine": "heuristic"},
                }
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr("ai_codescan.miss_review.is_available", lambda _provider: True)
    monkeypatch.setattr("ai_codescan.miss_review.subprocess.run", fake_subprocess_run)
    monkeypatch.setattr(
        "ai_codescan.miss_review.write_llm_cmd_script",
        lambda path, _llm: path,
    )

    db_path = repo_dir / "index.duckdb"
    run_dir = repo_dir / "runs" / "test"
    run_dir.mkdir(parents=True)
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    conn.close()
    result = run_miss_review(
        candidates_path=candidates_path,
        repo_dir=repo_dir,
        db_path=db_path,
        run_dir=run_dir,
        max_candidates=10,
        llm=LLMConfig(provider="claude"),
    )

    assert result["executed"] is True
    assert result["reviews"] == 1
    proposal_path = run_dir / "model_proposals" / "B-miss-0001.json"
    assert proposal_path.is_file()
    proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
    assert proposal["classification"] == "new-finding"


def test_ingest_miss_reviews_skips_malformed_files(tmp_path: Path) -> None:
    review_dir = tmp_path / "miss_reviews"
    review_dir.mkdir()
    (review_dir / "ok.json").write_text(
        json.dumps(
            {
                "candidate_id": "B-miss-ok",
                "classification": "false-positive",
                "confidence": "high",
                "rationale": "owner check is present",
                "evidence": ["a:1"],
                "proposal": {},
            }
        ),
        encoding="utf-8",
    )
    (review_dir / "bad.json").write_text("not json", encoding="utf-8")

    reviews = ingest_miss_reviews(review_dir=review_dir, proposals_dir=tmp_path / "proposals")

    assert len(reviews) == 1
    assert reviews[0].candidate_id == "B-miss-ok"
    # False-positive reviews must not create a proposal stub.
    assert not (tmp_path / "proposals" / "B-miss-ok.json").is_file()
