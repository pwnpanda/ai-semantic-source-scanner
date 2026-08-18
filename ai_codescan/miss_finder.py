"""Deterministic high-recall candidate generation for issues static flows miss."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import duckdb

from ai_codescan.evidence import build_evidence_bundle, write_evidence_bundle
from ai_codescan.scoring import attach_scores, persist_candidate_scores, score_candidates
from ai_codescan.semantic_hotspots import SemanticHotspot, discover_semantic_hotspots

_RESOURCE_ID_RE = re.compile(
    r"(?i)(?:^|[^a-z])(?:id|user_id|userid|tenant_id|tenantid|account_id|accountid|"
    r"order_id|orderid|project_id|projectid|org_id|orgid)(?:$|[^a-z])"
)
_ADMIN_RE = re.compile(r"(?i)(admin|manage|delete|export|import|impersonat|role|permission)")
_STATE_CHANGE_RE = re.compile(
    # Cover JS/Python/Go bare verbs (post/put/patch/delete) AND Spring's
    # ``@PostMapping`` / ``@PutMapping`` / ``@PatchMapping`` / ``@DeleteMapping``
    # annotations (regex word boundaries don't fire at case changes, so
    # ``DeleteMapping`` is not matched by ``\bdelete\b``). The trailing
    # ``Mapping`` suffix is the Spring/JAX-RS marker.
    r"(?i)(\bpost\b|\bput\b|\bpatch\b|\bdelete\b|"
    r"map(?:post|put|patch|delete)|"
    r"(?:post|put|patch|delete)Mapping)"
)
_AUTHZ_RE = re.compile(
    r"(?i)(authoriz|authent|permission|policy|require.*role|require.*auth|"
    r"require.*admin|isowner|is_owner|tenant|hasaccess|has_access|guard)"
)
_MIN_FLOW_STEP_PARTS = 2
_FLOW_COVERAGE_LINE_WINDOW = 5
_MAX_DISPLAY_TEXT = 500
_VECTOR_CWE = {
    "authz/bola": "CWE-639",
    "authz/bfla": "CWE-862",
    "authn/missing-authn": "CWE-287",
}
_HIGH_CONFIDENCE_FLOW_VALUES = {"definite", "high"}
_ID_HASH_LEN = 12


def _stable_candidate_id(*, file: str, line: int, vector: str) -> str:
    """Deterministic id derived from the entrypoint location + vector.

    Phase 2: replaces the prior sequential `B-miss-{:04d}` scheme so the
    `candidate_id` survives re-indexing and re-runs of `miss-finder`. The
    `review_verdicts` table keys on this id; stability across runs means
    verdicts are no longer orphaned when miss-finder runs again.

    Deliberately omits `heuristic` (the human-readable rule label) so minor
    wording changes to the rule do not shift every id; the `vector` carries
    the canonical concern.
    """
    blob = f"{file}\x00{line}\x00{vector}".encode()
    digest = hashlib.sha1(blob, usedforsecurity=False).hexdigest()[:_ID_HASH_LEN]
    return f"B-miss-{digest}"


@dataclass(frozen=True, slots=True)
class MissCandidate:
    id: str
    stream: str
    concern: str
    vector: str
    cwe: str
    file: str
    line: int
    name: str
    heuristic: str
    evidence: str
    overlap_with_deterministic: tuple[str, ...] = ()
    signal_strength: str = "contextual"
    requires_llm_validation: bool = True
    related_lines: tuple[int, ...] = ()

    def to_jsonable(self) -> dict[str, Any]:
        record = asdict(self)
        record["overlap_with_deterministic"] = list(self.overlap_with_deterministic)
        record["related_lines"] = list(self.related_lines)
        return record


@dataclass(frozen=True, slots=True)
class RiskMapEntry:
    kind: str
    signature: str
    file: str
    line: int
    haystack: str
    has_authz: bool
    covered_cwes: frozenset[str]


def _compact_text(value: str, *, max_chars: int = _MAX_DISPLAY_TEXT) -> str:
    compact = re.sub(r"\s+", " ", value).strip()
    if len(compact) <= max_chars:
        return compact
    return f"{compact[: max_chars - 3]}..."


def _nearby_authz_signal(conn: duckdb.DuckDBPyConnection, *, file: str, line: int) -> bool:
    rows = conn.execute(
        """
        SELECT display_name
        FROM symbols
        WHERE file = ?
          AND ABS(range_start - ?) <= 80
        """,
        [file, line],
    ).fetchall()
    if any(_AUTHZ_RE.search(str(name or "")) for (name,) in rows):
        return True
    xrefs = conn.execute(
        """
        SELECT kind
        FROM xrefs
        WHERE file = ?
          AND ABS(line - ?) <= 80
        """,
        [file, line],
    ).fetchall()
    return any(_AUTHZ_RE.search(str(kind or "")) for (kind,) in xrefs)


def _covered_cwes_by_flow(conn: duckdb.DuckDBPyConnection, *, file: str, line: int) -> set[str]:
    rows = conn.execute("SELECT cwe, confidence, steps_json FROM flows").fetchall()
    covered: set[str] = set()
    for cwe, confidence, steps_json in rows:
        if str(confidence or "").lower() not in _HIGH_CONFIDENCE_FLOW_VALUES:
            continue
        try:
            steps = json.loads(steps_json or "[]")
        except json.JSONDecodeError:
            continue
        for step in steps:
            if not isinstance(step, list) or len(step) < _MIN_FLOW_STEP_PARTS:
                continue
            try:
                step_file = str(step[0])
                step_line = int(step[1] or 0)
            except (TypeError, ValueError):
                continue
            if step_file == file and abs(step_line - line) <= _FLOW_COVERAGE_LINE_WINDOW:
                covered.add(str(cwe or ""))
    return covered


def build_risk_map(conn: duckdb.DuckDBPyConnection) -> list[RiskMapEntry]:
    """Build per-entrypoint semantic risk context for miss-finder rules."""
    rows = conn.execute(
        """
        SELECT symbol_id, kind, signature, file, line
        FROM entrypoints
        WHERE file IS NOT NULL
        ORDER BY file, line, signature
        """
    ).fetchall()
    entries: list[RiskMapEntry] = []
    for _symbol_id, kind, signature, file, line_raw in rows:
        file_s = str(file or "")
        line = int(line_raw or 0)
        sig = str(signature or "")
        haystack = f"{kind} {sig} {file_s}"
        entries.append(
            RiskMapEntry(
                kind=str(kind or ""),
                signature=sig,
                file=file_s,
                line=line,
                haystack=haystack,
                has_authz=_nearby_authz_signal(conn, file=file_s, line=line),
                covered_cwes=frozenset(_covered_cwes_by_flow(conn, file=file_s, line=line)),
            )
        )
    return entries


def build_miss_candidates(conn: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    """Return high-recall Stream B candidates for non-source/sink bug classes."""
    candidates: list[MissCandidate] = []
    seen: set[tuple[str, str, int, str]] = set()
    for risk in build_risk_map(conn):
        display_sig = _compact_text(risk.signature)
        display_evidence = _compact_text(risk.haystack)
        added_indices: list[int] = []
        covered_cwes = risk.covered_cwes
        context = (risk.file, risk.line, display_sig, added_indices)

        def add(
            rule: tuple[str, str, str, str],
            *,
            entry_context: tuple[str, int, str, list[int]],
            entry_covered_cwes: frozenset[str] = covered_cwes,
        ) -> None:
            """Recall-First Invariant 3: same-CWE deterministic coverage nearby
            does NOT drop the miss-finder candidate. It surfaces as the
            `overlap_with_deterministic` annotation so the scorer can demote."""
            concern, vector, heuristic, evidence = rule
            cwe = _VECTOR_CWE[vector]
            candidate_file, candidate_line, candidate_name, entry_added_indices = entry_context
            key = (candidate_file, vector, candidate_line, heuristic)
            if key in seen:
                return
            seen.add(key)
            entry_added_indices.append(len(candidates))
            candidates.append(
                MissCandidate(
                    id=_stable_candidate_id(
                        file=candidate_file, line=candidate_line, vector=vector
                    ),
                    stream="B",
                    concern=concern,
                    vector=vector,
                    cwe=cwe,
                    file=candidate_file,
                    line=candidate_line,
                    name=candidate_name,
                    heuristic=heuristic,
                    evidence=evidence,
                    overlap_with_deterministic=tuple(sorted(entry_covered_cwes)),
                )
            )

        if _RESOURCE_ID_RE.search(risk.haystack) and not risk.has_authz:
            add(
                (
                    "resource-id-without-nearby-authz",
                    "authz/bola",
                    "entrypoint has a resource identifier and no nearby authz-looking symbol",
                    display_evidence,
                ),
                entry_context=context,
            )
        if _ADMIN_RE.search(risk.haystack) and not risk.has_authz:
            add(
                (
                    "privileged-route-without-nearby-authz",
                    "authz/bfla",
                    "entrypoint looks privileged and no nearby authz-looking symbol was found",
                    display_evidence,
                ),
                entry_context=context,
            )
        if _STATE_CHANGE_RE.search(risk.haystack) and not risk.has_authz:
            add(
                (
                    "state-changing-route-without-nearby-authn",
                    "authn/missing-authn",
                    "state-changing entrypoint has no nearby authn/authz-looking symbol",
                    display_evidence,
                ),
                entry_context=context,
            )
    for hotspot in discover_semantic_hotspots(conn):
        _append_semantic_hotspot(candidates, seen, hotspot)

    # Overlap with nearby deterministic flows is recorded as the
    # structured `overlap_with_deterministic` field on each candidate
    # (set inside add()). The scorer turns that into an
    # `overlap_with_deterministic` factor; we no longer also mutate the
    # human-readable `evidence` string here (Invariant 3).
    return [candidate.to_jsonable() for candidate in candidates]


def _append_semantic_hotspot(
    candidates: list[MissCandidate],
    seen: set[tuple[str, str, int, str]],
    hotspot: SemanticHotspot,
) -> None:
    """Append a source-aware hotspot without turning it into a proven finding."""
    key = (hotspot.file, hotspot.vector, hotspot.line, hotspot.heuristic)
    if key in seen:
        return
    seen.add(key)
    candidates.append(
        MissCandidate(
            id=_stable_candidate_id(
                file=hotspot.file,
                line=hotspot.line,
                vector=hotspot.vector,
            ),
            stream="B",
            concern=hotspot.concern,
            vector=hotspot.vector,
            cwe=hotspot.cwe,
            file=hotspot.file,
            line=hotspot.line,
            name=hotspot.name,
            heuristic=hotspot.heuristic,
            evidence=hotspot.evidence,
            signal_strength=hotspot.signal_strength,
            requires_llm_validation=hotspot.requires_llm_validation,
            related_lines=hotspot.related_lines,
        )
    )


def write_miss_candidates(
    conn: duckdb.DuckDBPyConnection,
    *,
    out_path: Path,
    bundles_dir: Path | None = None,
) -> list[dict[str, Any]]:
    candidates = build_miss_candidates(conn)
    scores = score_candidates(conn, candidates)
    persist_candidate_scores(conn, scores)
    enriched = attach_scores(candidates, scores)
    enriched.sort(
        key=lambda candidate: (
            -float(candidate.get("score") or 0.0),
            str(candidate.get("id") or ""),
        )
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written_candidates: list[dict[str, Any]] = []
    with out_path.open("w", encoding="utf-8") as f:
        for candidate in enriched:
            output_candidate = candidate
            if bundles_dir is not None:
                bundle = build_evidence_bundle(conn, candidate)
                bundle_json, bundle_md = write_evidence_bundle(bundle, bundles_dir=bundles_dir)
                output_candidate = {
                    **candidate,
                    "bundle_json": str(bundle_json),
                    "bundle_md": str(bundle_md),
                }
            written_candidates.append(output_candidate)
            f.write(json.dumps(output_candidate, sort_keys=True))
            f.write("\n")
    return written_candidates
