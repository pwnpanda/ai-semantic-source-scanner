"""Tests for deterministic high-recall miss-finder candidates."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
import pytest
from typer.testing import CliRunner

import ai_codescan.miss_finder as miss_finder_module
from ai_codescan.cli import app
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.miss_finder import build_miss_candidates, write_miss_candidates
from ai_codescan.semantic_hotspots import SemanticHotspot

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def _connect(tmp_path: Path) -> duckdb.DuckDBPyConnection:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    return conn


def test_build_miss_candidates_id_is_content_addressed_and_stable(tmp_path: Path) -> None:
    """Phase 2: miss-finder candidate IDs must be content-addressed so that
    re-running the miss-finder on the same repo produces the same IDs. This
    makes review_verdicts.candidate_id a reliable primary key across runs."""
    conn = _connect(tmp_path)
    source = (tmp_path / "Program.cs").as_posix()
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'MapDelete /admin/users/{id}', ?, 42)",
        [source],
    )

    first = build_miss_candidates(conn)
    second = build_miss_candidates(conn)

    assert [c["id"] for c in first] == [c["id"] for c in second], (
        "candidate IDs must be deterministic across runs"
    )
    # IDs must be derived from file/line/vector — distinct candidates from the
    # same entrypoint (BOLA, BFLA, missing-authn) must have distinct IDs.
    ids = {c["id"] for c in first}
    assert len(ids) == len(first)
    # IDs must NOT depend on sequential ordering (the old behaviour).
    for candidate in first:
        assert not candidate["id"].endswith("-0001"), (
            "sequential ordering leaks via id suffix — use content hash instead"
        )


def test_build_miss_candidates_id_differs_per_line(tmp_path: Path) -> None:
    """Same vector + same file but different lines must produce different IDs."""
    conn = _connect(tmp_path)
    source = (tmp_path / "server.js").as_posix()
    conn.execute(
        "INSERT INTO entrypoints VALUES "
        "(NULL, 'http_route', 'app.delete /admin/users/{id}', ?, 10)",
        [source],
    )
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'app.delete /admin/orgs/{id}', ?, 20)",
        [source],
    )

    candidates = build_miss_candidates(conn)
    by_line = {c["line"]: c["id"] for c in candidates if c["vector"] == "authz/bola"}
    assert len(by_line) == 2
    assert by_line[10] != by_line[20]


def test_semantic_candidates_with_same_stable_identity_are_deduplicated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _connect(tmp_path)
    shared = {
        "concern": "generic concern",
        "vector": "workflow/validation-bypass",
        "cwe": "CWE-693",
        "line": 12,
        "name": "execute",
        "evidence": "if (options.skipValidation)",
    }
    hotspots = [
        SemanticHotspot(
            file="/cache/one/sample-deadbeef/source/src/Handler.kt",
            heuristic="first wording",
            **shared,
        ),
        SemanticHotspot(
            file="/different/cache/sample-deadbeef/source/src/Handler.kt",
            heuristic="reworded heuristic",
            **shared,
        ),
    ]
    monkeypatch.setattr(
        miss_finder_module,
        "discover_semantic_hotspots",
        lambda _conn: hotspots,
    )

    candidates = build_miss_candidates(conn)

    assert len(candidates) == 1
    assert len({candidate["id"] for candidate in candidates}) == 1


def test_build_miss_candidates_from_entrypoint_risk_signals(tmp_path: Path) -> None:
    conn = _connect(tmp_path)
    source = (tmp_path / "Program.cs").as_posix()
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'MapDelete /admin/users/{id}', ?, 42)",
        [source],
    )

    candidates = build_miss_candidates(conn)

    vectors = {candidate["vector"] for candidate in candidates}
    assert {"authz/bola", "authz/bfla", "authn/missing-authn"} <= vectors
    assert {candidate["cwe"] for candidate in candidates} >= {"CWE-639", "CWE-862", "CWE-287"}
    assert all(candidate["stream"] == "B" for candidate in candidates)


def test_build_miss_candidates_suppressed_by_nearby_authz_signal(tmp_path: Path) -> None:
    conn = _connect(tmp_path)
    source = (tmp_path / "Program.cs").as_posix()
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'MapDelete /admin/users/{id}', ?, 42)",
        [source],
    )
    conn.execute(
        """
        INSERT INTO symbols
          (id, sym, kind, file, range_start, range_end, type, display_name)
        VALUES ('S-auth', 'RequireAuthorization', 'method', ?, 44, 45, NULL, 'RequireAuthorization')
        """,
        [source],
    )

    candidates = build_miss_candidates(conn)

    assert candidates == []


def test_build_miss_candidates_marks_near_existing_flow_without_touching_previous(
    tmp_path: Path,
) -> None:
    conn = _connect(tmp_path)
    source = (tmp_path / "Program.cs").as_posix()
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'GET /orders/{id}', ?, 10)",
        [source],
    )
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'GET /health', ?, 50)",
        [source],
    )
    conn.execute(
        """
        INSERT INTO flows (fid, tid, sid, cwe, engine, steps_json, sarif_ref, confidence)
        VALUES ('F1', NULL, NULL, 'CWE-89', ?, ?, NULL, 'high')
        """,
        ["joern", json.dumps([[source, 50]])],
    )

    candidates = build_miss_candidates(conn)

    assert len(candidates) == 1
    assert "near existing flow" not in candidates[0]["evidence"]


def test_build_miss_candidates_keeps_same_cwe_overlap_with_annotation(
    tmp_path: Path,
) -> None:
    """Recall-First Invariant 3: a same-CWE deterministic flow nearby must NOT
    drop the miss-finder candidate. The candidate stays visible and is
    annotated so the scorer (and reviewers) can deprioritise it."""
    conn = _connect(tmp_path)
    source = (tmp_path / "Program.cs").as_posix()
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'GET /orders/{id}', ?, 10)",
        [source],
    )
    conn.execute(
        """
        INSERT INTO flows (fid, tid, sid, cwe, engine, steps_json, sarif_ref, confidence)
        VALUES ('F-bola', NULL, NULL, 'CWE-639', ?, ?, NULL, 'definite')
        """,
        ["codeql", json.dumps([[source, 10]])],
    )

    candidates = build_miss_candidates(conn)
    bola = next((c for c in candidates if c["vector"] == "authz/bola"), None)

    assert bola is not None, "miss-finder must keep same-CWE candidate (Invariant 3)"
    overlap = bola.get("overlap_with_deterministic") or []
    assert "CWE-639" in overlap, "overlap CWE must be annotated"


def test_bola_fixture_positive_route_is_flagged(tmp_path: Path) -> None:
    conn = _connect(tmp_path)
    source = (FIXTURES / "tiny-bola-positive" / "server.js").as_posix()
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'app.get /orders/{order_id}', ?, 4)",
        [source],
    )

    candidates = build_miss_candidates(conn)

    assert any(candidate["vector"] == "authz/bola" for candidate in candidates)


def test_bola_fixture_clean_route_is_not_flagged(tmp_path: Path) -> None:
    conn = _connect(tmp_path)
    source = (FIXTURES / "tiny-bola-clean" / "server.js").as_posix()
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'app.get /orders/{order_id}', ?, 8)",
        [source],
    )
    conn.execute(
        """
        INSERT INTO symbols
          (id, sym, kind, file, range_start, range_end, type, display_name)
        VALUES ('S-has-access', 'hasAccess', 'function', ?, 4, 6, NULL, 'hasAccess')
        """,
        [source],
    )

    candidates = build_miss_candidates(conn)

    assert not any(candidate["vector"] == "authz/bola" for candidate in candidates)


def test_write_miss_candidates_persists_scores_and_jsonl(tmp_path: Path) -> None:
    conn = _connect(tmp_path)
    source = (tmp_path / "api.ts").as_posix()
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'app.post /orders/{order_id}', ?, 7)",
        [source],
    )
    out = tmp_path / "miss_candidates.jsonl"

    candidates = write_miss_candidates(conn, out_path=out)

    assert out.is_file()
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert rows == candidates
    score_count = conn.execute("SELECT COUNT(*) FROM candidate_scores").fetchone()
    assert score_count is not None
    assert score_count[0] == len(candidates)
    assert all("score_label" in candidate for candidate in candidates)


def test_write_miss_candidates_writes_exploratory_bundles(tmp_path: Path) -> None:
    conn = _connect(tmp_path)
    source = tmp_path / "api.ts"
    source.write_text("app.get('/orders/:order_id', handler)\n", encoding="utf-8")
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'app.get /orders/{order_id}', ?, 1)",
        [source.as_posix()],
    )

    candidates = write_miss_candidates(
        conn,
        out_path=tmp_path / "miss_candidates.jsonl",
        bundles_dir=tmp_path / "miss_bundles",
    )

    assert candidates[0]["bundle_json"]
    assert Path(candidates[0]["bundle_json"]).is_file()
    assert Path(candidates[0]["bundle_md"]).is_file()


def test_miss_finder_cli_writes_default_output(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    repo = cache / "repo-1"
    repo.mkdir(parents=True)
    conn = duckdb.connect(str(repo / "index.duckdb"))
    apply_schema(conn)
    source = (tmp_path / "api.py").as_posix()
    conn.execute(
        "INSERT INTO entrypoints VALUES (NULL, 'http_route', 'POST /admin/export', ?, 3)",
        [source],
    )
    conn.close()

    result = runner.invoke(app, ["--cache-dir", str(cache), "miss-finder", "--repo-id", "repo-1"])

    assert result.exit_code == 0, result.stdout
    assert "wrote" in result.stdout
    assert "bundles" in result.stdout
    assert (repo / "miss_candidates.jsonl").is_file()
    assert (repo / "miss_bundles").is_dir()
