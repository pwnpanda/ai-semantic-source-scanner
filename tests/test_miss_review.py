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
    run_miss_review,
    stage_miss_review_queue,
)
from ai_codescan.review_cache import build_review_cache_key


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


def test_stage_miss_review_queue_uses_score_not_input_order(tmp_path: Path) -> None:
    candidates = [
        {"id": "low", "score": 0.2, "vector": "authz/bola"},
        {"id": "high", "score": 0.8, "vector": "authz/bola"},
        {"id": "medium", "score": 0.5, "vector": "xml/xxe"},
    ]

    selected = stage_miss_review_queue(
        candidates,
        queue_path=tmp_path / "queue.jsonl",
        max_candidates=2,
    )

    assert [candidate["id"] for candidate in selected] == ["high", "medium"]


def test_stage_miss_review_queue_keeps_issue_family_diversity(tmp_path: Path) -> None:
    candidates = [
        {"id": "logging-high", "score": 0.9, "vector": "logging/sensitive-object"},
        {"id": "logging-next", "score": 0.8, "vector": "logging/sensitive-object"},
        {"id": "approval", "score": 0.4, "vector": "workflow/stale-approval"},
    ]

    selected = stage_miss_review_queue(
        candidates,
        queue_path=tmp_path / "queue.jsonl",
        max_candidates=2,
    )

    assert [candidate["id"] for candidate in selected] == ["logging-high", "approval"]


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


def _write_queued_markers(env: dict[str, str]) -> None:
    done_dir = Path(env["AI_CODESCAN_RUN_DIR"]) / ".done-miss-review"
    done_dir.mkdir(parents=True, exist_ok=True)
    queue_path = Path(env["AI_CODESCAN_MISS_QUEUE"])
    for line in queue_path.read_text(encoding="utf-8").splitlines():
        candidate = json.loads(line)
        marker = {
            "evidence_fingerprint": candidate["review_evidence_fingerprint"],
            "review_fingerprint": candidate["review_fingerprint"],
            "provider": candidate["review_provider"],
            "model": candidate["review_model"],
        }
        (done_dir / candidate["id"]).write_text(json.dumps(marker), encoding="utf-8")


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
        llm=LLMConfig(provider="codex", model="gpt-5.6-codex"),
    )

    assert result["executed"] is False
    assert result["staged"] == 1
    queue_path = repo_dir / "miss_review_queue.jsonl"
    assert queue_path.is_file()
    assert "B-miss-0001" in queue_path.read_text(encoding="utf-8")
    [queued] = [json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines()]
    assert queued["review_provider"] == "codex"
    assert queued["review_model"] == "gpt-5.6-codex"
    assert queued["review_fingerprint"] != queued["review_evidence_fingerprint"]


def test_run_miss_review_removes_obsolete_generated_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    candidates_path = repo_dir / "miss_candidates.jsonl"
    candidates_path.write_text(
        json.dumps(
            {
                "id": "B-miss-current",
                "score": 0.8,
                "vector": "secrets/yaml-user-info-literal",
                "review_fingerprint": "current-fingerprint",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    review_dir = repo_dir / "miss_reviews"
    done_dir = repo_dir / ".done-miss-review"
    run_dir = repo_dir / "runs" / "test"
    findings_dir = run_dir / "findings"
    proposals_dir = run_dir / "model_proposals"
    for directory in (review_dir, done_dir, findings_dir, proposals_dir):
        directory.mkdir(parents=True)

    for candidate_id in ("B-miss-current", "B-miss-obsolete"):
        (review_dir / f"{candidate_id}.json").write_text("{}", encoding="utf-8")
        (done_dir / candidate_id).write_text("old-fingerprint", encoding="utf-8")
        (done_dir / f"{candidate_id}.stdout").write_text(
            "old sensitive prompt",
            encoding="utf-8",
        )
        finding_id = candidate_id.removeprefix("B-miss-")
        (findings_dir / f"F-miss-{finding_id}.md").write_text("stale", encoding="utf-8")
        (proposals_dir / f"{candidate_id}.json").write_text(
            "not json"
            if candidate_id == "B-miss-obsolete"
            else json.dumps({"candidate_id": candidate_id}),
            encoding="utf-8",
        )
        (proposals_dir / f"proposal-{candidate_id}.json").write_text(
            json.dumps({"nomination_id": candidate_id}),
            encoding="utf-8",
        )
    unrelated = findings_dir / "F-static.md"
    unrelated.write_text("keep", encoding="utf-8")
    unrelated_proposal = proposals_dir / "proposal-static.json"
    unrelated_proposal.write_text(
        json.dumps({"nomination_id": "N-static"}),
        encoding="utf-8",
    )
    malformed_generated_proposal = proposals_dir / "proposal-malformed.json"
    malformed_generated_proposal.write_text("not json", encoding="utf-8")

    db_path = repo_dir / "index.duckdb"
    result = run_miss_review(
        candidates_path=candidates_path,
        repo_dir=repo_dir,
        db_path=db_path,
        run_dir=run_dir,
        max_candidates=10,
        llm=LLMConfig(provider="claude"),
    )

    assert result["executed"] is False
    assert not list(review_dir.glob("B-miss-*.json"))
    assert not list(done_dir.glob("B-miss-*"))
    assert not list(findings_dir.glob("F-miss-*.md"))
    assert not list(proposals_dir.glob("B-miss-*.json"))
    assert not list(proposals_dir.glob("proposal-B-miss-*.json"))
    assert unrelated.read_text(encoding="utf-8") == "keep"
    assert unrelated_proposal.is_file()
    assert not malformed_generated_proposal.exists()


def test_run_miss_review_invalidates_marker_with_malformed_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    candidates_path = repo_dir / "miss_candidates.jsonl"
    candidates_path.write_text(
        json.dumps(
            {
                "id": "B-miss-current",
                "score": 0.8,
                "vector": "workflow/stale-approval",
                "review_fingerprint": "current-fingerprint",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    review_dir = repo_dir / "miss_reviews"
    done_dir = repo_dir / ".done-miss-review"
    proposals_dir = repo_dir / "runs" / "test" / "model_proposals"
    for directory in (review_dir, done_dir, proposals_dir):
        directory.mkdir(parents=True)
    (review_dir / "B-miss-current.json").write_text("{}", encoding="utf-8")
    (done_dir / "B-miss-current").write_text("current-fingerprint", encoding="utf-8")
    stale_proposal = proposals_dir / "proposal-stale.json"
    stale_proposal.write_text(
        json.dumps({"nomination_id": "B-miss-current"}),
        encoding="utf-8",
    )

    run_miss_review(
        candidates_path=candidates_path,
        repo_dir=repo_dir,
        db_path=repo_dir / "index.duckdb",
        run_dir=repo_dir / "runs" / "test",
        max_candidates=10,
        llm=LLMConfig(provider="claude"),
    )

    assert not (review_dir / "B-miss-current.json").exists()
    assert not (done_dir / "B-miss-current").exists()
    assert not stale_proposal.exists()


def test_provider_change_purges_unbacked_persisted_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    candidates_path = repo_dir / "miss_candidates.jsonl"
    candidates_path.write_text(
        json.dumps(
            {
                "id": "B-miss-current",
                "score": 0.8,
                "vector": "workflow/stale-approval",
                "review_fingerprint": "current-evidence",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    review_dir = repo_dir / "miss_reviews"
    done_dir = repo_dir / ".done-miss-review"
    review_dir.mkdir()
    done_dir.mkdir()
    (review_dir / "B-miss-current.json").write_text(
        json.dumps(
            {
                "candidate_id": "B-miss-current",
                "classification": "false-positive",
                "confidence": "high",
                "rationale": "old Claude review",
                "evidence": [],
                "proposal": {},
            }
        ),
        encoding="utf-8",
    )
    claude_key = build_review_cache_key(
        "current-evidence",
        LLMConfig(provider="claude", model="opus"),
    )
    (done_dir / "B-miss-current").write_text(
        json.dumps(claude_key.to_jsonable()),
        encoding="utf-8",
    )
    db_path = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)
    conn.execute(
        """
        INSERT INTO review_verdicts
          (nomination_id, finding_id, candidate_id, verdict, reviewer)
        VALUES ('B-miss-current', 'B-miss-current', 'B-miss-current',
                'false-positive', 'miss_reviewer')
        """
    )
    conn.close()

    run_miss_review(
        candidates_path=candidates_path,
        repo_dir=repo_dir,
        db_path=db_path,
        run_dir=repo_dir / "runs" / "test",
        max_candidates=10,
        llm=LLMConfig(provider="codex", model="gpt-5.6-codex"),
    )

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM review_verdicts WHERE reviewer = 'miss_reviewer'"
        ).fetchone()
    finally:
        conn.close()
    assert count == (0,)


def test_run_miss_review_invokes_loop_when_llm_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A model-gap review becomes one schema-valid model proposal."""
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
                    "classification": "needs-model-extension",
                    "confidence": "medium",
                    "rationale": "no owner check on resource-id route",
                    "evidence": ["/tmp/server.js:5"],
                    "proposal": {
                        "cwe": "CWE-639",
                        "source_pattern": "resource id route",
                        "sink_pattern": "repository lookup",
                        "sanitizer_pattern": "owner check",
                        "target_engine": "heuristic",
                    },
                }
            ),
            encoding="utf-8",
        )
        _write_queued_markers(env)

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
    [proposal_path] = list((run_dir / "model_proposals").glob("proposal-*.json"))
    proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
    assert proposal["proposal_id"]
    assert proposal["nomination_id"] == "B-miss-0001"
    assert proposal["source_pattern"] == "resource id route"
    assert not (run_dir / "model_proposals" / "B-miss-0001.json").exists()


def test_run_miss_review_replaces_outputs_when_current_review_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    candidates_path = repo_dir / "miss_candidates.jsonl"
    candidates_path.write_text(
        json.dumps(
            {
                "id": "B-miss-0001",
                "stream": "B",
                "vector": "authz/bola",
                "review_fingerprint": "current-fingerprint",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    run_dir = repo_dir / "runs" / "test"
    findings_dir = run_dir / "findings"
    proposals_dir = run_dir / "model_proposals"
    review_dir = repo_dir / "miss_reviews"
    done_dir = repo_dir / ".done-miss-review"
    findings_dir.mkdir(parents=True)
    proposals_dir.mkdir()
    review_dir.mkdir()
    done_dir.mkdir()
    (review_dir / "B-miss-0001.json").write_text(
        json.dumps(
            {
                "candidate_id": "B-miss-0001",
                "classification": "needs-model-extension",
                "confidence": "medium",
                "rationale": "old review",
                "evidence": [],
                "proposal": {"cwe": "CWE-639"},
            }
        ),
        encoding="utf-8",
    )
    (done_dir / "B-miss-0001").write_text("current-fingerprint", encoding="utf-8")
    stale_finding = findings_dir / "F-miss-0001.md"
    stale_finding.write_text("stale finding", encoding="utf-8")
    stale_proposal = proposals_dir / "proposal-stale.json"
    stale_proposal.write_text(
        json.dumps({"nomination_id": "B-miss-0001"}),
        encoding="utf-8",
    )

    def fake_subprocess_run(argv: list[str], *, env: dict[str, str], check: bool) -> None:
        current_review_dir = Path(env["AI_CODESCAN_MISS_REVIEW_DIR"])
        (current_review_dir / "B-miss-0001.json").write_text(
            json.dumps(
                {
                    "candidate_id": "B-miss-0001",
                    "classification": "false-positive",
                    "confidence": "high",
                    "rationale": "current review rejects the candidate",
                    "evidence": [],
                    "proposal": {},
                }
            ),
            encoding="utf-8",
        )
        _write_queued_markers(env)

    monkeypatch.setattr("ai_codescan.miss_review.is_available", lambda _provider: True)
    monkeypatch.setattr("ai_codescan.miss_review.subprocess.run", fake_subprocess_run)
    monkeypatch.setattr(
        "ai_codescan.miss_review.write_llm_cmd_script",
        lambda path, _llm: path,
    )
    db_path = repo_dir / "index.duckdb"
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

    assert result["reviews"] == 1
    assert not stale_finding.exists()
    assert not stale_proposal.exists()


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

    reviews = ingest_miss_reviews(review_dir=review_dir)

    assert len(reviews) == 1
    assert reviews[0].candidate_id == "B-miss-ok"


def test_ingest_miss_reviews_ignores_candidates_outside_current_queue(tmp_path: Path) -> None:
    review_dir = tmp_path / "reviews"
    review_dir.mkdir()
    for candidate_id in ("current", "stale"):
        (review_dir / f"{candidate_id}.json").write_text(
            json.dumps(
                {
                    "candidate_id": candidate_id,
                    "classification": "new-finding",
                    "confidence": "medium",
                    "rationale": "candidate rationale",
                    "evidence": ["source.kt:1"],
                    "proposal": {"cwe": "CWE-862"},
                }
            ),
            encoding="utf-8",
        )

    reviews = ingest_miss_reviews(
        review_dir=review_dir,
        candidate_ids=frozenset({"current"}),
    )

    assert [review.candidate_id for review in reviews] == ["current"]
