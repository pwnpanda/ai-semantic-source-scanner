"""Regression coverage for Kotlin/Spring semantic miss-finder nominations."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import duckdb
import pytest

from ai_codescan.eval import load_eval_cases, run_ai_codescan_case
from ai_codescan.miss_finder import build_miss_candidates, write_miss_candidates
from ai_codescan.prep import run_prep

EVAL_TARGETS = Path(__file__).parents[1] / "eval-targets"
POSITIVE = EVAL_TARGETS / "kotlin-spring-semantic-hotspots"
NEGATIVE = EVAL_TARGETS / "kotlin-spring-semantic-hotspots-safe"

EXPECTED_VECTORS = {
    "workflow/approval-ownership",
    "workflow/stale-approval",
    "workflow/validation-bypass",
    "workflow/fail-open-policy-lookup",
    "authn/request-controlled-identity",
    "authz/peer-guard-omission",
    "xml/unsafe-jaxp-identity-transform",
    "logging/sensitive-object",
    "dos/unbounded-archive-expansion",
    "injection/content-disposition-filename",
    "secrets/yaml-user-info-literal",
}


def _has_node() -> bool:
    return shutil.which("node") is not None


def _candidates_for(target: Path, cache_root: Path) -> list[dict[str, object]]:
    _snapshot, db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    conn = duckdb.connect(str(db_path))
    try:
        return build_miss_candidates(conn)
    finally:
        conn.close()


@pytest.mark.skipif(not _has_node(), reason="node runtime required for Kotlin AST extraction")
def test_kotlin_semantic_hotspots_cover_reviewed_issue_shapes(tmp_path: Path) -> None:
    candidates = _candidates_for(POSITIVE, tmp_path / "positive-cache")

    vectors = {str(candidate["vector"]) for candidate in candidates}
    assert vectors >= EXPECTED_VECTORS
    for candidate in candidates:
        if candidate["vector"] == "secrets/yaml-user-info-literal":
            assert candidate["requires_llm_validation"] is False
        elif candidate["vector"] in EXPECTED_VECTORS:
            assert candidate["requires_llm_validation"] is True

    serialized = json.dumps(candidates)
    assert "synthetic-password" not in serialized
    assert "<redacted literal>" in serialized


@pytest.mark.skipif(not _has_node(), reason="node runtime required for Kotlin AST extraction")
def test_hardened_kotlin_pair_does_not_emit_semantic_hotspots(tmp_path: Path) -> None:
    candidates = _candidates_for(NEGATIVE, tmp_path / "negative-cache")

    vectors = {str(candidate["vector"]) for candidate in candidates}
    assert EXPECTED_VECTORS.isdisjoint(vectors)


@pytest.mark.skipif(not _has_node(), reason="node runtime required for Kotlin AST extraction")
def test_semantic_hotspots_are_ranked_before_contextual_route_smells(tmp_path: Path) -> None:
    cache_root = tmp_path / "rank-cache"
    _snapshot, db_path = run_prep(
        POSITIVE,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    out_path = tmp_path / "candidates.jsonl"
    conn = duckdb.connect(str(db_path))
    try:
        written = write_miss_candidates(conn, out_path=out_path)
    finally:
        conn.close()

    scores = [float(candidate["score"]) for candidate in written]
    assert scores == sorted(scores, reverse=True)
    first_contextual = next(
        (
            index
            for index, candidate in enumerate(written)
            if candidate["signal_strength"] == "contextual"
        ),
        len(written),
    )
    assert all(
        candidate["signal_strength"] in {"strong", "deterministic"}
        for candidate in written[:first_contextual]
    )


@pytest.mark.skipif(not _has_node(), reason="node runtime required for Kotlin AST extraction")
def test_semantic_hotspot_eval_pair_passes_miss_finder_engine(tmp_path: Path) -> None:
    cases = {case.id: case for case in load_eval_cases(EVAL_TARGETS)}

    positive = run_ai_codescan_case(
        cases["kotlin-spring-semantic-hotspots"],
        cache_root=tmp_path / "eval-positive",
    )
    negative = run_ai_codescan_case(
        cases["kotlin-spring-semantic-hotspots-safe"],
        cache_root=tmp_path / "eval-negative",
    )

    assert positive.status == "pass", positive.to_jsonable()
    assert negative.status == "pass", negative.to_jsonable()
