"""Deterministic high-recall candidate generation for issues static flows miss."""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_left
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import duckdb

from ai_codescan.evidence import build_evidence_bundle, write_evidence_bundle
from ai_codescan.review_cache import read_review_cache_key
from ai_codescan.scoring import (
    attach_scores,
    persist_candidate_scores,
    score_candidates,
    select_review_candidates,
)
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
_AUTHZ_LINE_WINDOW = 80
_MAX_DISPLAY_TEXT = 500
_VECTOR_CWE = {
    "authz/bola": "CWE-639",
    "authz/bfla": "CWE-862",
    "authn/missing-authn": "CWE-287",
}
_HIGH_CONFIDENCE_FLOW_VALUES = {"definite", "high"}
_ID_HASH_LEN = 12
_CACHE_REPO_COMPONENT_RE = re.compile(r".+-[0-9a-f]{8}$", re.IGNORECASE)
_REVIEW_FINGERPRINT_VERSION = "miss-review-input-v4"
_MISS_REVIEW_CLASSIFICATIONS = frozenset(
    {
        "new-finding",
        "covered-by-static",
        "false-positive",
        "needs-model-extension",
        "needs-human-context",
    }
)
_REVIEW_PROMPT_PATH = (
    Path(__file__).resolve().parent / "skills" / "miss_reviewer" / "prompts" / "reviewer.md"
)


def _canonical_candidate_file(file: str) -> str:
    normalized = file.replace("\\", "/")
    parts = normalized.split("/")
    source_indices = [index for index, part in enumerate(parts) if part == "source"]
    for index in source_indices:
        if index > 0 and _CACHE_REPO_COMPONENT_RE.fullmatch(parts[index - 1]):
            return "/".join(parts[index + 1 :])
    return normalized


def _stable_candidate_id(*, file: str, line: int, vector: str) -> str:
    """Deterministic id derived from the entrypoint location + vector.

    Phase 2: replaces the prior sequential `B-miss-{:04d}` scheme so the
    `candidate_id` survives re-indexing and re-runs of `miss-finder`. The
    `review_verdicts` table keys on this id; stability across runs means
    verdicts are no longer orphaned when miss-finder runs again.

    Cache snapshots live below a generated ``source`` directory. Hashing only
    the path below that boundary keeps ids stable when the cache root changes.
    The hash deliberately omits `heuristic` (the human-readable rule label) so
    wording changes do not shift ids; the `vector` carries the canonical concern.
    """
    canonical_file = _canonical_candidate_file(file)
    blob = f"{canonical_file}\x00{line}\x00{vector}".encode()
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
    redacted_lines: tuple[int, ...] = ()

    def to_jsonable(self) -> dict[str, Any]:
        record = asdict(self)
        record["overlap_with_deterministic"] = list(self.overlap_with_deterministic)
        record["related_lines"] = list(self.related_lines)
        record["redacted_lines"] = list(self.redacted_lines)
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


def _authz_lines_by_file(conn: duckdb.DuckDBPyConnection) -> dict[str, list[int]]:
    lines_by_file: dict[str, list[int]] = defaultdict(list)
    symbol_rows = conn.execute("SELECT file, range_start, display_name FROM symbols").fetchall()
    for file, line, name in symbol_rows:
        if file and line is not None and _AUTHZ_RE.search(str(name or "")):
            lines_by_file[str(file)].append(int(line))
    xref_rows = conn.execute("SELECT file, line, kind FROM xrefs").fetchall()
    for file, line, kind in xref_rows:
        if file and line is not None and _AUTHZ_RE.search(str(kind or "")):
            lines_by_file[str(file)].append(int(line))
    return {file: sorted(lines) for file, lines in lines_by_file.items()}


def _flow_coverage_by_file(
    conn: duckdb.DuckDBPyConnection,
) -> dict[str, list[tuple[int, str]]]:
    rows = conn.execute("SELECT cwe, confidence, steps_json FROM flows").fetchall()
    coverage_by_file: dict[str, list[tuple[int, str]]] = defaultdict(list)
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
            coverage_by_file[step_file].append((step_line, str(cwe or "")))
    return {file: sorted(coverage) for file, coverage in coverage_by_file.items()}


def _has_line_near(lines: list[int], target: int, *, window: int) -> bool:
    index = bisect_left(lines, target - window)
    return index < len(lines) and lines[index] <= target + window


def _covered_cwes_near(coverage: list[tuple[int, str]], line: int) -> frozenset[str]:
    index = bisect_left(coverage, (line - _FLOW_COVERAGE_LINE_WINDOW, ""))
    covered: set[str] = set()
    while index < len(coverage) and coverage[index][0] <= line + _FLOW_COVERAGE_LINE_WINDOW:
        covered.add(coverage[index][1])
        index += 1
    return frozenset(covered)


def build_risk_map(conn: duckdb.DuckDBPyConnection) -> list[RiskMapEntry]:
    """Build per-entrypoint semantic risk context for miss-finder rules."""
    authz_lines = _authz_lines_by_file(conn)
    flow_coverage = _flow_coverage_by_file(conn)
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
                has_authz=_has_line_near(
                    authz_lines.get(file_s, []),
                    line,
                    window=_AUTHZ_LINE_WINDOW,
                ),
                covered_cwes=_covered_cwes_near(flow_coverage.get(file_s, []), line),
            )
        )
    return entries


def build_miss_candidates(
    conn: duckdb.DuckDBPyConnection,
    *,
    source_root: Path,
) -> list[dict[str, Any]]:
    """Return high-recall Stream B candidates for non-source/sink bug classes."""
    candidates: list[MissCandidate] = []
    seen: set[tuple[str, str, int]] = set()
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
            key = (_canonical_candidate_file(candidate_file), vector, candidate_line)
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
    for hotspot in discover_semantic_hotspots(conn, source_root=source_root):
        _append_semantic_hotspot(candidates, seen, hotspot)

    # Overlap with nearby deterministic flows is recorded as the
    # structured `overlap_with_deterministic` field on each candidate
    # (set inside add()). The scorer turns that into an
    # `overlap_with_deterministic` factor; we no longer also mutate the
    # human-readable `evidence` string here (Invariant 3).
    return [candidate.to_jsonable() for candidate in candidates]


def _append_semantic_hotspot(
    candidates: list[MissCandidate],
    seen: set[tuple[str, str, int]],
    hotspot: SemanticHotspot,
) -> None:
    """Append a source-aware hotspot without turning it into a proven finding."""
    key = (_canonical_candidate_file(hotspot.file), hotspot.vector, hotspot.line)
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
            redacted_lines=hotspot.redacted_lines,
        )
    )


def _clear_generated_bundles(bundles_dir: Path) -> None:
    """Remove generated bundles before replacing them with current evidence."""
    if not bundles_dir.is_dir():
        return
    for suffix in ("json", "md"):
        for bundle_path in bundles_dir.glob(f"B-miss-*.{suffix}"):
            bundle_path.unlink(missing_ok=True)


def _review_input_fingerprint(
    candidate: dict[str, Any],
    *,
    prompt_sha256: str,
    source_sha256: str,
) -> str:
    payload = json.dumps(
        {
            "candidate": candidate,
            "prompt_sha256": prompt_sha256,
            "source_sha256": source_sha256,
            "version": _REVIEW_FINGERPRINT_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _redactions_by_file(candidates: list[dict[str, Any]]) -> dict[str, list[int]]:
    """Return every source line that must be hidden in bundles for each file."""
    by_file: dict[str, set[int]] = {}
    for candidate in candidates:
        file = str(candidate.get("file") or "")
        if not file:
            continue
        lines = candidate.get("redacted_lines") or []
        if not isinstance(lines, (list, tuple)):
            continue
        by_file.setdefault(file, set()).update(
            line for raw_line in lines if (line := _positive_int(raw_line)) is not None
        )
    return {file: sorted(lines) for file, lines in by_file.items()}


def _positive_int(value: object) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _table_exists(conn: duckdb.DuckDBPyConnection, table: str) -> bool:
    row = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
        [table],
    ).fetchone()
    return row is not None and int(row[0]) > 0


def _marker_matches(review_state_dir: Path, candidate_id: str, fingerprint: str) -> bool:
    marker = review_state_dir / ".done-miss-review" / candidate_id
    review_path = review_state_dir / "miss_reviews" / f"{candidate_id}.json"
    try:
        cache_key = read_review_cache_key(marker)
        if cache_key is None or cache_key.evidence_fingerprint != fingerprint:
            return False
        review = json.loads(review_path.read_text(encoding="utf-8"))
        return (
            isinstance(review, dict)
            and str(review.get("candidate_id") or "") == candidate_id
            and str(review.get("classification") or "") in _MISS_REVIEW_CLASSIFICATIONS
        )
    except (OSError, json.JSONDecodeError):
        return False


def _purge_stale_miss_feedback(
    conn: duckdb.DuckDBPyConnection,
    *,
    candidate_fingerprints: dict[str, str],
    review_state_dir: Path,
) -> None:
    """Discard persisted review signals that no longer match current source."""
    if not _table_exists(conn, "review_verdicts"):
        return
    rows = conn.execute(
        """
        SELECT COALESCE(NULLIF(candidate_id, ''), nomination_id), finding_id
        FROM review_verdicts
        WHERE reviewer = 'miss_reviewer'
        """
    ).fetchall()
    stale_rows = {
        (str(candidate_id or ""), str(finding_id or ""))
        for candidate_id, finding_id in rows
        if not (fingerprint := candidate_fingerprints.get(str(candidate_id or "")))
        or not _marker_matches(review_state_dir, str(candidate_id or ""), fingerprint)
    }
    if not stale_rows:
        return
    candidate_parameters = [(candidate_id,) for candidate_id, _finding_id in stale_rows]
    conn.executemany(
        """
        DELETE FROM review_verdicts
        WHERE reviewer = 'miss_reviewer'
          AND COALESCE(NULLIF(candidate_id, ''), nomination_id) = ?
        """,
        candidate_parameters,
    )
    if _table_exists(conn, "adversarial_challenges"):
        finding_parameters = [
            (finding_id,) for _candidate_id, finding_id in stale_rows if finding_id
        ]
        if not finding_parameters:
            return
        conn.executemany(
            "DELETE FROM adversarial_challenges WHERE finding_id = ?",
            finding_parameters,
        )


def write_miss_candidates(  # noqa: PLR0913 - one positional arg; controls are keyword-only
    conn: duckdb.DuckDBPyConnection,
    *,
    out_path: Path,
    source_root: Path,
    bundles_dir: Path | None = None,
    max_bundles: int | None = None,
    review_state_dir: Path | None = None,
) -> list[dict[str, Any]]:
    candidates = build_miss_candidates(conn, source_root=source_root)
    redactions_by_file = _redactions_by_file(candidates)
    candidates = [
        {
            **candidate,
            "redacted_lines": redactions_by_file.get(str(candidate.get("file") or ""), []),
        }
        for candidate in candidates
    ]
    prompt_sha256 = hashlib.sha256(_REVIEW_PROMPT_PATH.read_bytes()).hexdigest()
    source_digests = {
        str(path): str(sha256 or "")
        for path, sha256 in conn.execute("SELECT path, sha256 FROM files").fetchall()
    }
    candidate_fingerprints = {
        str(candidate.get("id") or ""): _review_input_fingerprint(
            candidate,
            prompt_sha256=prompt_sha256,
            source_sha256=source_digests.get(str(candidate.get("file") or ""), ""),
        )
        for candidate in candidates
        if candidate.get("id")
    }
    _purge_stale_miss_feedback(
        conn,
        candidate_fingerprints=candidate_fingerprints,
        review_state_dir=review_state_dir or out_path.parent,
    )
    scores = score_candidates(conn, candidates, source_root=source_root)
    conn.execute("DELETE FROM candidate_scores WHERE candidate_id LIKE 'B-miss-%'")
    persist_candidate_scores(conn, scores)
    enriched = attach_scores(candidates, scores)
    enriched.sort(
        key=lambda candidate: (
            -float(candidate.get("score") or 0.0),
            str(candidate.get("id") or ""),
        )
    )
    candidates_with_bundles = (
        enriched
        if max_bundles is None
        else select_review_candidates(enriched, max_candidates=max_bundles)
    )
    bundle_candidate_ids = {str(candidate.get("id") or "") for candidate in candidates_with_bundles}
    if bundles_dir is not None:
        _clear_generated_bundles(bundles_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written_candidates: list[dict[str, Any]] = []
    with out_path.open("w", encoding="utf-8") as f:
        for candidate in enriched:
            review_candidate = candidate
            candidate_id = str(review_candidate.get("id") or "")
            output_candidate = {
                **review_candidate,
                "review_evidence_fingerprint": candidate_fingerprints.get(candidate_id, ""),
                "review_fingerprint": candidate_fingerprints.get(candidate_id, ""),
            }
            if bundles_dir is not None and candidate_id in bundle_candidate_ids:
                bundle = build_evidence_bundle(
                    conn,
                    review_candidate,
                    source_root=source_root,
                )
                bundle_json, bundle_md = write_evidence_bundle(bundle, bundles_dir=bundles_dir)
                output_candidate = {
                    **output_candidate,
                    "bundle_json": str(bundle_json),
                    "bundle_md": str(bundle_md),
                }
            written_candidates.append(output_candidate)
            f.write(json.dumps(output_candidate, sort_keys=True))
            f.write("\n")
    return written_candidates
