"""Candidate scoring for review prioritization.

Scores are deliberately non-destructive: they rank and explain candidates,
but do not suppress plausible findings. False negatives are more expensive
than review noise, so early versions should prefer ``low`` over hiding data.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import duckdb

from ai_codescan.mitigations import mitigations_for_candidate

SCORER_VERSION = "candidate-score-v1"
_HIGH_SCORE = 0.75
_MEDIUM_SCORE = 0.45
_LOW_SCORE = 0.2

_DANGEROUS_SINK_CLASSES: dict[str, float] = {
    "sql.exec": 0.18,
    "cmd.shell": 0.22,
    "code.exec": 0.22,
    "deser.unsafe": 0.2,
    "ssrf": 0.18,
    "log.sensitive": 0.08,
    "fs.read": 0.12,
    "html.write": 0.1,
    "firestore.idor": 0.16,
    "firestore.write": 0.14,
    "firestore.query": 0.14,
    # Phase 18: open redirect (CWE-601) — credential-phishing impact, less
    # severe than RCE/SQLi so the boost is modest.
    "open.redirect": 0.1,
    # SSTI typically reaches RCE on Jinja2/Mako/ERB, so weight it like
    # code.exec rather than html.write.
    "ssti": 0.22,
    # Email / SMTP header injection (CWE-93): user-controlled to/subject
    # with CRLF can splice Bcc / alter envelopes. Medium severity.
    "email.send": 0.1,
    # Phase 19: client-side path traversal (CWE-22, sink_class cspt). Impact
    # is reaching unintended same-origin endpoints — similar weight to fs.read.
    "cspt": 0.12,
    # Phase 20: XXE (CWE-611) reaches file disclosure and often SSRF, so it
    # sits near deser.unsafe rather than the lighter injection classes.
    "xml.parse": 0.18,
    # Prototype pollution (CWE-1321) is usually a gadget-chain prerequisite
    # rather than direct RCE — real but rarely standalone-critical.
    "proto.pollute": 0.14,
    # Header write / response splitting (CWE-93). Most modern runtimes strip
    # CRLF from header values, so the base weight is deliberately low; the
    # reviewer confirms whether the runtime actually sanitises.
    "header.write": 0.08,
    # Phase 21. NoSQL operator injection reaches auth bypass and data
    # disclosure — comparable to sql.exec.
    "nosql.query": 0.18,
    # LDAP / XPath injection subvert query logic (auth bypass, data
    # disclosure) but rarely reach code execution.
    "ldap.query": 0.14,
    "xpath.query": 0.14,
    # ReDoS is availability-only, so this stays low and leans on the reviewer.
    # Go's linear-time standard regexp engine is intentionally not modelled.
    "redos": 0.06,
}

_LOW_SIGNAL_PARTS = {
    "test",
    "tests",
    "__tests__",
    "spec",
    "fixtures",
    "fixture",
    "examples",
    "example",
    "mocks",
    "__mocks__",
    "vendor",
    "node_modules",
    "generated",
    "dist",
    "build",
}

_SAFE_PARAMETERIZATION_HINTS = {
    "parameterized",
    "prepared",
    "bound",
    "safe",
    "literal",
}

_SEMANTIC_SIGNAL_WEIGHTS = {
    "strong": 0.12,
    "deterministic": 0.2,
}


def select_review_candidates(
    candidates: list[dict[str, Any]],
    *,
    max_candidates: int,
) -> list[dict[str, Any]]:
    """Select a score-ranked queue while retaining issue-family diversity."""
    if max_candidates <= 0:
        return []
    ranked = sorted(
        enumerate(candidates),
        key=lambda item: (-float(item[1].get("score") or 0.0), item[0]),
    )
    selected: list[dict[str, Any]] = []
    selected_indices: set[int] = set()
    selected_vectors: set[str] = set()
    for index, candidate in ranked:
        vector = str(candidate.get("vector") or candidate.get("concern") or "")
        if vector in selected_vectors:
            continue
        selected.append(candidate)
        selected_indices.add(index)
        selected_vectors.add(vector)
        if len(selected) == max_candidates:
            return selected
    selected.extend(candidate for index, candidate in ranked if index not in selected_indices)
    return selected[:max_candidates]


@dataclass(frozen=True, slots=True)
class ScoreFactor:
    name: str
    value: float
    reason: str


@dataclass(frozen=True, slots=True)
class CandidateScore:
    candidate_id: str
    flow_id: str | None
    stream: str
    score: float
    label: str
    processing_bucket: str
    factors: list[ScoreFactor]
    mitigations: list[dict[str, str]] = field(default_factory=list)
    scorer: str = SCORER_VERSION

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "score_label": self.label,
            "processing_bucket": self.processing_bucket,
            "mitigations": self.mitigations,
            "score_factors": [asdict(f) for f in self.factors],
            "score_version": self.scorer,
        }


def _clamp_score(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _label_for(score: float) -> str:
    if score >= _HIGH_SCORE:
        return "high"
    if score >= _MEDIUM_SCORE:
        return "medium"
    if score >= _LOW_SCORE:
        return "low"
    return "probably-safe"


def _processing_bucket_for(label: str) -> str:
    return {
        "high": "report",
        "medium": "llm-review",
        "low": "explore",
        "probably-safe": "audit",
    }[label]


def _path_parts(path: str) -> set[str]:
    return {part.lower() for part in PurePosixPath(path).parts}


def _path_penalty(candidate: dict[str, Any]) -> ScoreFactor | None:
    path = str(candidate.get("source_loc") or candidate.get("file") or "")
    if not path:
        return None
    if _path_parts(path) & _LOW_SIGNAL_PARTS:
        return ScoreFactor(
            "low_signal_path",
            -0.35,
            "candidate is in a test, fixture, example, generated, vendor, or build path",
        )
    return None


def _source_file_for_candidate(candidate: dict[str, Any]) -> str:
    source_loc = str(candidate.get("source_loc") or "")
    if source_loc:
        return source_loc.rpartition(":")[0]
    return str(candidate.get("file") or "")


def _sidecar_path_for_source(file: str) -> Path | None:
    path = Path(file)
    parts = path.parts
    if "source" not in parts:
        return None
    source_index = len(parts) - 1 - list(reversed(parts)).index("source")
    repo_root = Path(*parts[:source_index])
    rel = Path(*parts[source_index + 1 :])
    if not rel.name:
        return None
    return repo_root / "sidecars" / rel.with_suffix(rel.suffix + ".enrich.jsonl")


def _sidecar_factor(candidate: dict[str, Any]) -> ScoreFactor | None:
    sidecar_path = _sidecar_path_for_source(_source_file_for_candidate(candidate))
    if sidecar_path is None or not sidecar_path.is_file():
        return None
    kinds: set[str] = set()
    for raw in sidecar_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            kinds.add(str(record.get("kind") or ""))
    useful = kinds & {"source", "sink", "flow", "entrypoint"}
    if not useful:
        return None
    return ScoreFactor(
        "sidecar_context",
        0.06,
        "sidecar records add context: " + ",".join(sorted(useful)),
    )


def _adversarial_factor(
    conn: duckdb.DuckDBPyConnection,
    candidate_id: str,
) -> ScoreFactor | None:
    """Score factor from any adversarial challenge on this candidate's finding.

    Phase 13: after `adversarial-review` runs, a second model's challenge of
    the candidate's review verdict becomes a ranking signal. The mapping
    (disputed-TP demotes, disputed-FP re-elevates) lives in
    `adversarial_validator.adversarial_score_delta`. Returns None on the
    first scoring pass — the tables don't exist until a review + challenge
    have run.
    """
    if not candidate_id:
        return None
    tables = {
        str(row[0])
        for row in conn.execute("SELECT table_name FROM information_schema.tables").fetchall()
    }
    if "review_verdicts" not in tables or "adversarial_challenges" not in tables:
        return None
    row = conn.execute(
        "SELECT finding_id FROM review_verdicts WHERE candidate_id = ? LIMIT 1",
        [candidate_id],
    ).fetchone()
    if row is None or not row[0]:
        return None
    from ai_codescan.adversarial_validator import (  # noqa: PLC0415 - avoids an import cycle
        adversarial_score_delta,
        challenge_consensus_all,
    )

    consensus = challenge_consensus_all(conn).get(str(row[0]))
    if consensus is None:
        return None
    delta = adversarial_score_delta(consensus)
    if delta is None:
        return None
    name, value, reason = delta
    return ScoreFactor(name, value, reason)


def _has_entrypoint_nearby(conn: duckdb.DuckDBPyConnection, source_loc: str) -> bool:
    file, sep, raw_line = source_loc.rpartition(":")
    if not sep:
        return False
    try:
        line = int(raw_line)
    except ValueError:
        return False
    row = conn.execute(
        """
        SELECT 1
        FROM entrypoints
        WHERE file = ?
          AND ABS(COALESCE(line, 0) - ?) <= 40
        LIMIT 1
        """,
        [file, line],
    ).fetchone()
    return row is not None


def score_candidate(  # noqa: PLR0912, PLR0915 - factor accumulator is intentionally flat
    conn: duckdb.DuckDBPyConnection,
    candidate: dict[str, Any],
) -> CandidateScore:
    factors: list[ScoreFactor] = []
    stream = str(candidate.get("stream") or "")
    candidate_id = str(candidate.get("id") or "")
    flow_id = str(candidate["fid"]) if candidate.get("fid") else None

    score = 0.18
    if stream == "A":
        factors.append(ScoreFactor("static_flow", 0.22, "candidate has a traced static flow"))
        score += 0.22
    elif stream == "B":
        factors.append(ScoreFactor("heuristic_candidate", 0.08, "candidate came from a heuristic"))
        score += 0.08

    signal_strength = str(candidate.get("signal_strength") or "contextual")
    if signal_strength in _SEMANTIC_SIGNAL_WEIGHTS:
        signal_weight = _SEMANTIC_SIGNAL_WEIGHTS[signal_strength]
        factors.append(
            ScoreFactor(
                "semantic_signal",
                signal_weight,
                f"source-aware semantic pattern strength is {signal_strength}",
            )
        )
        score += signal_weight

    # Recall-First Invariant 6: co-location fallback flows are emitted by
    # Joern when the data-flow engine couldn't link source to sink. They are
    # weaker evidence — proximity, not actual reachability. Demote heavily
    # so they sort below real data-flow candidates without being dropped.
    flow_type = str(candidate.get("flow_type") or "dataflow")
    if flow_type == "co-location":
        factors.append(
            ScoreFactor(
                "colocation_fallback",
                -0.32,
                "flow came from Joern's co-location fallback (proximity, not data-flow proof)",
            )
        )
        score -= 0.32

    engine = str(candidate.get("engine") or "")
    if "+" in engine:
        factors.append(ScoreFactor("engine_consensus", 0.24, f"multiple engines agree: {engine}"))
        score += 0.24
    elif engine:
        factors.append(ScoreFactor("engine_signal", 0.1, f"reported by {engine}"))
        score += 0.1

    sink_class = str(candidate.get("sink_class") or "")
    if sink_class in _DANGEROUS_SINK_CLASSES:
        value = _DANGEROUS_SINK_CLASSES[sink_class]
        factors.append(ScoreFactor("dangerous_sink", value, f"sink class is {sink_class}"))
        score += value

    parameterization = str(candidate.get("parameterization") or "").lower()
    if parameterization == "unknown":
        factors.append(ScoreFactor("unknown_parameterization", 0.08, "parameterization is unknown"))
        score += 0.08
    elif any(hint in parameterization for hint in _SAFE_PARAMETERIZATION_HINTS):
        factors.append(
            ScoreFactor(
                "safe_parameterization_hint",
                -0.28,
                f"parameterization looks safer: {parameterization}",
            )
        )
        score -= 0.28

    source_loc = str(candidate.get("source_loc") or "")
    if not source_loc and candidate.get("file") and candidate.get("line"):
        source_loc = f"{candidate['file']}:{candidate['line']}"
    if source_loc and _has_entrypoint_nearby(conn, source_loc):
        factors.append(
            ScoreFactor("entrypoint_proximity", 0.16, "source is near a detected entrypoint")
        )
        score += 0.16

    if path_factor := _path_penalty(candidate):
        factors.append(path_factor)
        score += path_factor.value

    if sidecar_factor := _sidecar_factor(candidate):
        factors.append(sidecar_factor)
        score += sidecar_factor.value

    # Recall-First Invariant 3: miss-finder candidates that overlap with
    # nearby deterministic flows are demoted, never dropped. The miss-finder
    # writes the overlap CWE list to ``overlap_with_deterministic``.
    overlap_raw = candidate.get("overlap_with_deterministic") or ()
    overlap_cwes = [str(c) for c in overlap_raw if c]
    if overlap_cwes:
        own_cwe = str(candidate.get("cwe") or "")
        same_cwe = own_cwe and own_cwe in overlap_cwes
        value = -0.18 if same_cwe else -0.08
        if same_cwe:
            reason = (
                f"same-CWE deterministic flow nearby ({own_cwe}); "
                "reviewers should validate the existing flow first"
            )
        else:
            overlap_list = ",".join(overlap_cwes)
            reason = (
                f"deterministic flow nearby for {overlap_list}; "
                "this candidate covers a different concern"
            )
        factors.append(ScoreFactor("overlap_with_deterministic", value, reason))
        score += value

    mitigations = mitigations_for_candidate(conn, candidate)
    if mitigations:
        factors.append(
            ScoreFactor(
                "mitigation_signal",
                -0.18,
                "candidate has nearby mitigation evidence: "
                + ", ".join(signal["kind"] for signal in mitigations[:3]),
            )
        )
        score -= 0.18

    # Phase 13: an adversarial challenger's verdict on this candidate's
    # review verdict. Absent on the first scoring pass (no review yet).
    if adversarial := _adversarial_factor(conn, candidate_id):
        factors.append(adversarial)
        score += adversarial.value

    score = _clamp_score(score)
    label = _label_for(score)
    return CandidateScore(
        candidate_id=candidate_id,
        flow_id=flow_id,
        stream=stream,
        score=score,
        label=label,
        processing_bucket=_processing_bucket_for(label),
        factors=factors,
        mitigations=mitigations,
    )


def score_candidates(
    conn: duckdb.DuckDBPyConnection,
    candidates: list[dict[str, Any]],
) -> list[CandidateScore]:
    return [score_candidate(conn, candidate) for candidate in candidates]


def persist_candidate_scores(
    conn: duckdb.DuckDBPyConnection,
    scores: list[CandidateScore],
) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS candidate_scores (
          candidate_id VARCHAR PRIMARY KEY,
          flow_id VARCHAR,
          stream VARCHAR,
          score DOUBLE,
          label VARCHAR,
          processing_bucket VARCHAR,
          factors_json VARCHAR,
          scorer VARCHAR,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info('candidate_scores')").fetchall()
    }
    if "processing_bucket" not in columns:
        conn.execute("ALTER TABLE candidate_scores ADD COLUMN processing_bucket VARCHAR")
    for score in scores:
        conn.execute(
            """
            INSERT OR REPLACE INTO candidate_scores
              (
                candidate_id, flow_id, stream, score, label, processing_bucket,
                factors_json, scorer
              )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                score.candidate_id,
                score.flow_id,
                score.stream,
                score.score,
                score.label,
                score.processing_bucket,
                json.dumps([asdict(f) for f in score.factors], sort_keys=True),
                score.scorer,
            ],
        )


def attach_scores(
    candidates: list[dict[str, Any]],
    scores: list[CandidateScore],
) -> list[dict[str, Any]]:
    by_id = {score.candidate_id: score for score in scores}
    enriched: list[dict[str, Any]] = []
    for candidate in candidates:
        out = dict(candidate)
        score = by_id.get(str(candidate.get("id") or ""))
        if score is not None:
            out.update(score.to_jsonable())
        enriched.append(out)
    return enriched
