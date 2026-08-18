"""Tests for ai_codescan.scoring."""

import json
from pathlib import Path

import duckdb
import pytest

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.scoring import attach_scores, persist_candidate_scores, score_candidates


@pytest.mark.parametrize(
    ("sink_class", "expected_weight"),
    (
        ("xml.parse", 0.18),
        ("proto.pollute", 0.14),
        ("header.write", 0.08),
        ("nosql.query", 0.18),
        ("ldap.query", 0.14),
        ("xpath.query", 0.14),
        ("redos", 0.06),
    ),
)
def test_phase_20_21_sink_classes_contribute_expected_score(
    tmp_path: Path,
    sink_class: str,
    expected_weight: float,
) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    candidate = {
        "id": f"A-{sink_class}",
        "stream": "A",
        "fid": f"F-{sink_class}",
        "engine": "joern",
        "sink_class": sink_class,
    }

    score = score_candidates(conn, [candidate])[0]

    factor = next(item for item in score.factors if item.name == "dangerous_sink")
    assert factor.value == expected_weight


@pytest.mark.parametrize(
    ("signal_strength", "expected_weight"),
    (("strong", 0.12), ("deterministic", 0.2)),
)
def test_source_aware_semantic_strength_contributes_expected_score(
    tmp_path: Path,
    signal_strength: str,
    expected_weight: float,
) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    candidate = {
        "id": f"B-{signal_strength}",
        "stream": "B",
        "signal_strength": signal_strength,
    }

    score = score_candidates(conn, [candidate])[0]

    factor = next(item for item in score.factors if item.name == "semantic_signal")
    assert factor.value == expected_weight


def test_score_candidates_ranks_static_sql_flow_high(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    source = (tmp_path / "Program.cs").as_posix()
    conn.execute("INSERT INTO entrypoints VALUES (NULL, 'http_route', 'MapGet', ?, 14)", [source])
    candidate = {
        "id": "A-F1",
        "stream": "A",
        "fid": "F1",
        "engine": "codeql+joern",
        "source_loc": f"{source}:15",
        "sink_class": "sql.exec",
        "parameterization": "unknown",
    }

    score = score_candidates(conn, [candidate])[0]

    assert score.label == "high"
    assert score.processing_bucket == "report"
    assert score.score >= 0.75
    assert {factor.name for factor in score.factors} >= {
        "static_flow",
        "engine_consensus",
        "dangerous_sink",
        "entrypoint_proximity",
    }


def test_score_candidates_does_not_hide_fixture_candidates(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    candidate = {
        "id": "A-F1",
        "stream": "A",
        "fid": "F1",
        "engine": "joern",
        "source_loc": "/repo/tests/fixtures/Program.cs:15",
        "sink_class": "sql.exec",
        "parameterization": "unknown",
    }

    score = score_candidates(conn, [candidate])[0]

    assert score.label in {"low", "medium"}
    assert score.score > 0.0


def test_score_candidates_annotates_mitigation_signals(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    source = tmp_path / "Program.cs"
    source.write_text(
        "\n".join(
            [
                'var sql = "SELECT id FROM users WHERE id = @id";',
                "using var cmd = new SqliteCommand(sql, connection);",
                'cmd.Parameters.AddWithValue("@id", id);',
                "cmd.ExecuteReader();",
            ]
        ),
        encoding="utf-8",
    )
    conn.execute("INSERT INTO taint_sources VALUES ('T1', NULL, 'route', 'id', ?)", [f"{source}:1"])
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'ExecuteReader', 'unknown', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'joern', ?, NULL, 'inferred')",
        [f'[["{source}", 1], ["{source}", 4]]'],
    )
    candidate = {
        "id": "A-F1",
        "stream": "A",
        "fid": "F1",
        "cwe": "CWE-89",
        "sink_class": "sql.exec",
        "parameterization": "unknown",
    }

    score = score_candidates(conn, [candidate])[0]
    enriched = attach_scores([candidate], [score])[0]

    assert any(factor.name == "mitigation_signal" for factor in score.factors)
    assert enriched["mitigations"]


def test_score_candidates_demotes_colocation_fallback_flows(tmp_path: Path) -> None:
    """Recall-First Invariant 6: a co-location-fallback flow is demoted via a
    strong negative score factor, so it sorts below real data-flow candidates
    without being dropped."""
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    candidate = {
        "id": "A-colo",
        "stream": "A",
        "fid": "F-colo",
        "cwe": "CWE-79",
        "engine": "joern",
        "sink_class": "html.write",
        "flow_type": "co-location",
        "parameterization": "unknown",
    }
    real = {
        "id": "A-real",
        "stream": "A",
        "fid": "F-real",
        "cwe": "CWE-79",
        "engine": "joern",
        "sink_class": "html.write",
        "flow_type": "dataflow",
        "parameterization": "unknown",
    }
    scores = score_candidates(conn, [candidate, real])

    colo_factor = next(
        (factor for factor in scores[0].factors if factor.name == "colocation_fallback"),
        None,
    )
    assert colo_factor is not None
    assert colo_factor.value < 0
    assert scores[0].score < scores[1].score


def test_score_candidates_demotes_overlap_with_deterministic(tmp_path: Path) -> None:
    """Recall-First Invariant 3: an overlap_with_deterministic annotation on a
    miss-finder candidate adds a negative score factor so reviewers see the
    deterministic flow first, but the candidate is not hidden."""
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    candidate = {
        "id": "B-miss-001",
        "stream": "B",
        "vector": "authz/bola",
        "cwe": "CWE-639",
        "overlap_with_deterministic": ["CWE-639"],
    }

    score = score_candidates(conn, [candidate])[0]

    overlap_factor = next(
        (factor for factor in score.factors if factor.name == "overlap_with_deterministic"),
        None,
    )
    assert overlap_factor is not None, (
        "overlap candidates must carry an overlap_with_deterministic factor"
    )
    assert overlap_factor.value < 0, "overlap factor must be negative (demote, not boost)"


def test_score_candidates_uses_sidecar_context_when_available(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    repo = tmp_path / "cache" / "repo-id"
    source = repo / "source" / "src" / "handler.ts"
    sidecar = repo / "sidecars" / "src" / "handler.ts.enrich.jsonl"
    source.parent.mkdir(parents=True)
    sidecar.parent.mkdir(parents=True)
    source.write_text("export function handler(req) { return req.query.id; }\n", encoding="utf-8")
    sidecar.write_text(
        "\n".join(
            [
                json.dumps({"kind": "entrypoint", "line": 1}),
                json.dumps({"kind": "source", "line": 1}),
                "{not-json",
                json.dumps({"kind": "note", "line": 1}),
            ]
        ),
        encoding="utf-8",
    )
    candidate = {
        "id": "A-F2",
        "stream": "A",
        "fid": "F2",
        "source_loc": f"{source}:1",
    }

    score = score_candidates(conn, [candidate])[0]

    factor = next(factor for factor in score.factors if factor.name == "sidecar_context")
    assert factor.value > 0
    assert "entrypoint" in factor.reason
    assert "source" in factor.reason


def test_persist_and_attach_scores(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    candidate = {"id": "B-auth-S1", "stream": "B", "concern": "authz-callsite"}
    scores = score_candidates(conn, [candidate])

    persist_candidate_scores(conn, scores)
    enriched = attach_scores([candidate], scores)

    row = conn.execute(
        """
        SELECT candidate_id, label, processing_bucket
        FROM candidate_scores
        WHERE candidate_id = 'B-auth-S1'
        """
    ).fetchone()
    assert row == ("B-auth-S1", scores[0].label, scores[0].processing_bucket)
    assert enriched[0]["score"] == scores[0].score
    assert enriched[0]["processing_bucket"] == scores[0].processing_bucket
    assert enriched[0]["score_factors"]


def test_persist_scores_adds_processing_bucket_to_existing_table(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    conn.execute(
        """
        CREATE TABLE candidate_scores (
          candidate_id VARCHAR PRIMARY KEY,
          flow_id VARCHAR,
          stream VARCHAR,
          score DOUBLE,
          label VARCHAR,
          factors_json VARCHAR,
          scorer VARCHAR
        )
        """
    )
    candidate = {"id": "B-auth-S2", "stream": "B", "concern": "authz-callsite"}
    scores = score_candidates(conn, [candidate])

    persist_candidate_scores(conn, scores)

    columns = {row[1] for row in conn.execute("PRAGMA table_info('candidate_scores')").fetchall()}
    row = conn.execute(
        "SELECT processing_bucket FROM candidate_scores WHERE candidate_id = 'B-auth-S2'"
    ).fetchone()
    assert "processing_bucket" in columns
    assert row == (scores[0].processing_bucket,)
