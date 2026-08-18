"""Evidence bundle rendering for deterministic and exploratory candidates."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import duckdb

_DEFAULT_CONTEXT_LINES = 5
_MIN_FLOW_STEP_FIELDS = 2
_TRUNCATE_KEEP_EXCERPTS = 2
_CONFIG_SECRET_KEY_RE = re.compile(
    r"(?i)^\s*(?P<quote>[\"']?)[A-Za-z0-9_.-]*"
    r"(?:user[-_.]?info|password|secret|token|api[-_.]?key|credential)"
    r"[A-Za-z0-9_.-]*(?P=quote)\s*:"
)


@dataclass(frozen=True, slots=True)
class EvidenceExcerpt:
    file: str
    line: int
    context_start: int
    context_end: int
    code_excerpt: str


@dataclass(frozen=True, slots=True)
class EvidenceEntrypoint:
    kind: str
    signature: str
    file: str
    line: int


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    bundle_id: str
    candidate_id: str
    stream: str
    flow_id: str | None
    cwe: str | None
    source_loc: str
    source_name: str
    sink_name: str
    sink_class: str
    parameterization: str
    engine: str
    confidence: str
    score: float | None
    score_label: str | None
    score_factors: list[dict[str, Any]]
    mitigations: list[dict[str, Any]]
    entrypoints: list[EvidenceEntrypoint] = field(default_factory=list)
    excerpts: list[EvidenceExcerpt] = field(default_factory=list)
    questions: list[str] = field(default_factory=list)

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "candidate_id": self.candidate_id,
            "stream": self.stream,
            "flow_id": self.flow_id,
            "cwe": self.cwe,
            "source_loc": self.source_loc,
            "source_name": self.source_name,
            "sink_name": self.sink_name,
            "sink_class": self.sink_class,
            "parameterization": self.parameterization,
            "engine": self.engine,
            "confidence": self.confidence,
            "score": self.score,
            "score_label": self.score_label,
            "score_factors": self.score_factors,
            "mitigations": self.mitigations,
            "entrypoints": [asdict(e) for e in self.entrypoints],
            "excerpts": [asdict(e) for e in self.excerpts],
            "questions": self.questions,
        }


@dataclass(frozen=True, slots=True)
class _EvidenceMetadata:
    cwe: str | None
    engine: str
    confidence: str
    source_loc: str
    source_name: str
    sink_name: str
    sink_class: str
    parameterization: str
    flow_steps: list[tuple[str, int]]


def _redact_config_line(line: str) -> str:
    key, separator, _value = line.partition(":")
    if not separator:
        return "<redacted>"
    return f"{key}: <redacted>"


def _read_excerpt(
    file: Path,
    line: int,
    *,
    context_lines: int,
    redacted_lines: frozenset[int] = frozenset(),
) -> EvidenceExcerpt:
    start = max(1, line - context_lines)
    end = line + context_lines
    excerpt = ""
    actual_end = start - 1
    if file.is_file():
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
        kept = [
            _redact_config_line(value)
            if number in redacted_lines or (redacted_lines and _CONFIG_SECRET_KEY_RE.search(value))
            else value
            for number, value in enumerate(lines[start - 1 : end], start=start)
        ]
        excerpt = "\n".join(kept)
        actual_end = start + max(0, len(kept) - 1)
    return EvidenceExcerpt(
        file=file.as_posix(),
        line=line,
        context_start=start,
        context_end=actual_end,
        code_excerpt=excerpt,
    )


def _parse_loc(loc: str) -> tuple[str, int] | None:
    file, sep, raw_line = loc.rpartition(":")
    if not sep:
        return None
    try:
        line = int(raw_line)
    except ValueError:
        return None
    return (file, line)


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _flow_steps(steps_json: str) -> list[tuple[str, int]]:
    try:
        raw_steps = json.loads(steps_json or "[]")
    except json.JSONDecodeError:
        return []
    out: list[tuple[str, int]] = []
    for entry in raw_steps:
        if not isinstance(entry, list) or len(entry) < _MIN_FLOW_STEP_FIELDS:
            continue
        try:
            out.append((str(entry[0]), int(entry[1])))
        except (TypeError, ValueError):
            continue
    return out


def _entrypoints_near(
    conn: duckdb.DuckDBPyConnection,
    files: set[str],
    lines: set[int],
) -> list[EvidenceEntrypoint]:
    if not files:
        return []
    out: list[EvidenceEntrypoint] = []
    for file in sorted(files):
        rows = conn.execute(
            """
            SELECT kind, signature, file, line
            FROM entrypoints
            WHERE file = ?
            ORDER BY ABS(COALESCE(line, 0) - ?), line
            LIMIT 5
            """,
            [file, min(lines) if lines else 0],
        ).fetchall()
        for kind, signature, ep_file, line in rows:
            out.append(
                EvidenceEntrypoint(
                    kind=str(kind or ""),
                    signature=str(signature or ""),
                    file=str(ep_file or file),
                    line=int(line or 0),
                )
            )
    return out


def _score_factors(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    raw = candidate.get("score_factors") or []
    if isinstance(raw, list):
        return [dict(item) for item in raw if isinstance(item, dict)]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return [dict(item) for item in parsed if isinstance(item, dict)]
    return []


def _candidate_step_locs(
    candidate: dict[str, Any],
    *,
    source_loc: str,
    flow_steps: list[tuple[str, int]],
) -> list[tuple[str, int]]:
    step_locs = list(flow_steps)
    if not step_locs and source_loc and (parsed := _parse_loc(source_loc)):
        step_locs.append(parsed)
    candidate_file = str(candidate.get("file") or "")
    if (
        not step_locs
        and candidate_file
        and candidate.get("line")
        and (line := _int_or_none(candidate["line"]))
    ):
        step_locs.append((candidate_file, line))
    related_lines = candidate.get("related_lines") or []
    if candidate_file and isinstance(related_lines, list):
        for related_line in related_lines:
            if line := _int_or_none(related_line):
                step_locs.append((candidate_file, line))
    return step_locs


def _candidate_redacted_lines(candidate: dict[str, Any]) -> frozenset[int]:
    raw_lines = candidate.get("redacted_lines") or []
    if not isinstance(raw_lines, (list, tuple)):
        return frozenset()
    return frozenset(
        line for raw_line in raw_lines if (line := _int_or_none(raw_line)) is not None and line > 0
    )


def _review_questions(candidate: dict[str, Any], *, stream: str) -> list[str]:
    questions = [
        "Is attacker-controlled input reachable at the source?",
        "Does the data reach the sink without an effective mitigation?",
        "Is the vulnerable path reachable from an exposed entrypoint?",
    ]
    if stream == "B":
        questions.append("Is this heuristic candidate a real issue or only a hotspot?")
    if candidate.get("requires_llm_validation") is False:
        questions.append(
            "The source pattern itself is deterministic; what deployment context changes impact?"
        )
    return questions


def _secret_lines_by_file(candidate: dict[str, Any]) -> dict[str, frozenset[int]]:
    vector = str(candidate.get("vector") or "")
    if not vector.startswith("secrets/"):
        return {}
    file = str(candidate.get("file") or "")
    line = _int_or_none(candidate.get("line"))
    if not file or line is None:
        return {}
    return {file: frozenset({line})}


def _candidate_source_loc(candidate: dict[str, Any]) -> str:
    source_loc = str(candidate.get("source_loc") or "")
    line = _int_or_none(candidate.get("line"))
    if source_loc and line is not None and _parse_loc(source_loc) is None:
        return f"{source_loc}:{line}"
    if not source_loc and candidate.get("file") and line is not None:
        return f"{candidate['file']}:{line}"
    return source_loc or str(candidate.get("file") or "")


def _evidence_metadata(
    conn: duckdb.DuckDBPyConnection,
    candidate: dict[str, Any],
    flow_id: str | None,
) -> _EvidenceMetadata:
    values = _EvidenceMetadata(
        cwe=str(candidate.get("cwe") or "") or None,
        engine=str(candidate.get("engine") or ""),
        confidence=str(candidate.get("confidence") or ""),
        source_loc=_candidate_source_loc(candidate),
        source_name=str(candidate.get("source_name") or candidate.get("name") or ""),
        sink_name=str(candidate.get("lib") or ""),
        sink_class=str(candidate.get("sink_class") or ""),
        parameterization=str(candidate.get("parameterization") or ""),
        flow_steps=[],
    )
    if not flow_id:
        return values
    row = conn.execute(
        """
        SELECT f.cwe, f.engine, f.confidence, f.steps_json,
               s.evidence_loc, s.key, t.class, t.lib, t.parameterization
        FROM flows f
        LEFT JOIN taint_sources s ON s.tid = f.tid
        LEFT JOIN taint_sinks t ON t.sid = f.sid
        WHERE f.fid = ?
        """,
        [flow_id],
    ).fetchone()
    if row is None:
        return values
    cwe, engine, confidence, steps, source_loc, source, sink_class, sink, parameterization = row
    return _EvidenceMetadata(
        cwe=str(cwe or values.cwe or "") or None,
        engine=str(engine or values.engine),
        confidence=str(confidence or values.confidence),
        source_loc=str(source_loc or values.source_loc),
        source_name=str(source or values.source_name),
        sink_name=str(sink or values.sink_name),
        sink_class=str(sink_class or values.sink_class),
        parameterization=str(parameterization or values.parameterization),
        flow_steps=_flow_steps(str(steps or "")),
    )


def build_evidence_bundle(
    conn: duckdb.DuckDBPyConnection,
    candidate: dict[str, Any],
    *,
    context_lines: int = _DEFAULT_CONTEXT_LINES,
) -> EvidenceBundle:
    """Build an evidence bundle for a queue candidate.

    Stream A candidates get source/sink/flow metadata from DuckDB. Stream B
    candidates may not have a flow, so they receive a location-focused bundle
    that still gives the reviewer source context and score reasons.
    """
    candidate_id = str(candidate.get("id") or "candidate")
    flow_id = str(candidate["fid"]) if candidate.get("fid") else None
    stream = str(candidate.get("stream") or "")
    metadata = _evidence_metadata(conn, candidate, flow_id)

    step_locs = _candidate_step_locs(
        candidate,
        source_loc=metadata.source_loc,
        flow_steps=metadata.flow_steps,
    )

    effective_context_lines = context_lines
    if candidate.get("signal_strength") in {"strong", "deterministic"}:
        effective_context_lines = max(context_lines, 10)

    excerpts: list[EvidenceExcerpt] = []
    seen: set[tuple[str, int]] = set()
    secret_lines = _secret_lines_by_file(candidate)
    candidate_file = str(candidate.get("file") or "")
    candidate_redactions = _candidate_redacted_lines(candidate)
    for file, line in step_locs:
        key = (file, line)
        if key in seen:
            continue
        seen.add(key)
        redacted_lines = secret_lines.get(file, frozenset())
        if file == candidate_file:
            redacted_lines |= candidate_redactions
        excerpts.append(
            _read_excerpt(
                Path(file),
                line,
                context_lines=effective_context_lines,
                redacted_lines=redacted_lines,
            )
        )

    files = {file for file, _line in step_locs}
    lines = {line for _file, line in step_locs}
    questions = _review_questions(candidate, stream=stream)

    return EvidenceBundle(
        bundle_id=f"E-{candidate_id}",
        candidate_id=candidate_id,
        stream=stream,
        flow_id=flow_id,
        cwe=metadata.cwe,
        source_loc=metadata.source_loc,
        source_name=metadata.source_name,
        sink_name=metadata.sink_name,
        sink_class=metadata.sink_class,
        parameterization=metadata.parameterization,
        engine=metadata.engine,
        confidence=metadata.confidence,
        score=float(candidate["score"]) if candidate.get("score") is not None else None,
        score_label=str(candidate.get("score_label") or "") or None,
        score_factors=_score_factors(candidate),
        mitigations=[
            dict(item) for item in candidate.get("mitigations", []) if isinstance(item, dict)
        ],
        entrypoints=_entrypoints_near(conn, files, lines),
        excerpts=excerpts,
        questions=questions,
    )


def render_bundle_markdown(bundle: EvidenceBundle) -> str:
    lines = [
        f"# Evidence Bundle: {bundle.candidate_id}",
        "",
        f"- Stream: `{bundle.stream}`",
        f"- Flow: `{bundle.flow_id or ''}`",
        f"- CWE: `{bundle.cwe or ''}`",
        f"- Engine: `{bundle.engine}`",
        f"- Confidence: `{bundle.confidence}`",
        f"- Score: `{bundle.score if bundle.score is not None else ''}`"
        f" ({bundle.score_label or ''})",
        f"- Source: `{bundle.source_loc}` {bundle.source_name}",
        f"- Sink: `{bundle.sink_name}` `{bundle.sink_class}`",
        f"- Parameterization: `{bundle.parameterization}`",
        "",
    ]
    if bundle.score_factors:
        lines.extend(["## Score Factors", ""])
        for factor in bundle.score_factors:
            lines.append(
                f"- `{factor.get('name', '')}` {factor.get('value', '')}: "
                f"{factor.get('reason', '')}"
            )
        lines.append("")
    if bundle.mitigations:
        lines.extend(["## Mitigation Signals", ""])
        for signal in bundle.mitigations:
            lines.append(
                f"- `{signal.get('kind', '')}` {signal.get('confidence', '')}: "
                f"{signal.get('reason', '')}"
            )
        lines.append("")
    if bundle.entrypoints:
        lines.extend(["## Entrypoints", ""])
        for ep in bundle.entrypoints:
            lines.append(f"- {ep.file}:{ep.line} `{ep.kind}` {ep.signature}")
        lines.append("")
    if bundle.excerpts:
        lines.extend(["## Code", ""])
        for excerpt in bundle.excerpts:
            lines.append(f"### {excerpt.file}:{excerpt.line}")
            lines.append("")
            lines.append("```")
            lines.append(excerpt.code_excerpt)
            lines.append("```")
            lines.append("")
    lines.extend(["## Review Questions", ""])
    for question in bundle.questions:
        lines.append(f"- {question}")
    return "\n".join(lines).rstrip() + "\n"


def write_evidence_bundle(bundle: EvidenceBundle, *, bundles_dir: Path) -> tuple[Path, Path]:
    bundles_dir.mkdir(parents=True, exist_ok=True)
    json_path = bundles_dir / f"{bundle.candidate_id}.json"
    md_path = bundles_dir / f"{bundle.candidate_id}.md"
    json_path.write_text(
        json.dumps(bundle.to_jsonable(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    md_path.write_text(render_bundle_markdown(bundle), encoding="utf-8")
    return json_path, md_path


def _truncate_string(value: str, *, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    cut = max(0, max_chars - 3)
    return value[:cut] + "..."


def truncate_bundle_to(  # noqa: PLR0911 - progressive truncation: each step is an early-exit
    bundle: EvidenceBundle,
    *,
    max_bytes: int,
) -> EvidenceBundle:
    """Return a shrunk copy of `bundle` whose JSON encoding fits within `max_bytes`.

    Recall-First Invariant 4: oversized bundles must be truncated, not dropped.
    Shrink order, least-to-most aggressive:
      1. Trim intermediate excerpts (keep first and last).
      2. Shorten each remaining excerpt's `code_excerpt` text.
      3. Drop entrypoints beyond the first.
      4. Drop score factor reasons (keep names + values).
    The returned bundle carries `truncated_to=max_bytes` (mitigations entry) so
    the reviewer knows the bundle was shrunk.
    """

    def jsonable_size(b: EvidenceBundle) -> int:
        return len(json.dumps(b.to_jsonable(), sort_keys=True).encode("utf-8"))

    if jsonable_size(bundle) <= max_bytes:
        return bundle
    truncated_marker = {
        "kind": "bundle.truncated",
        "confidence": "info",
        "reason": f"bundle truncated to fit max_bundle_bytes={max_bytes}",
        "evidence": "size-cap",
    }
    mitigations = list(bundle.mitigations) + [truncated_marker]

    # Step 1: keep first and last excerpt only.
    excerpts = list(bundle.excerpts)
    if len(excerpts) > _TRUNCATE_KEEP_EXCERPTS:
        excerpts = [excerpts[0], excerpts[-1]]
    candidate = _replace_bundle(bundle, excerpts=excerpts, mitigations=mitigations)
    if jsonable_size(candidate) <= max_bytes:
        return candidate

    # Step 2: progressively trim each excerpt's code text.
    for cap in (400, 200, 100, 40):
        excerpts = [
            EvidenceExcerpt(
                file=e.file,
                line=e.line,
                context_start=e.context_start,
                context_end=e.context_end,
                code_excerpt=_truncate_string(e.code_excerpt, max_chars=cap),
            )
            for e in candidate.excerpts
        ]
        candidate = _replace_bundle(candidate, excerpts=excerpts)
        if jsonable_size(candidate) <= max_bytes:
            return candidate

    # Step 3: drop entrypoints beyond the first.
    if candidate.entrypoints:
        candidate = _replace_bundle(candidate, entrypoints=candidate.entrypoints[:1])
        if jsonable_size(candidate) <= max_bytes:
            return candidate

    # Step 4: drop score-factor reasons.
    factors_min = [
        {"name": f.get("name", ""), "value": f.get("value", 0)} for f in candidate.score_factors
    ]
    candidate = _replace_bundle(candidate, score_factors=factors_min)
    if jsonable_size(candidate) <= max_bytes:
        return candidate

    # Step 5: drop excerpts entirely — source/sink loc remain queryable from candidate metadata.
    candidate = _replace_bundle(candidate, excerpts=[])
    if jsonable_size(candidate) <= max_bytes:
        return candidate

    # Step 6: keep only a single shortened question.
    return EvidenceBundle(
        bundle_id=candidate.bundle_id,
        candidate_id=candidate.candidate_id,
        stream=candidate.stream,
        flow_id=candidate.flow_id,
        cwe=candidate.cwe,
        source_loc=candidate.source_loc,
        source_name=candidate.source_name,
        sink_name=candidate.sink_name,
        sink_class=candidate.sink_class,
        parameterization=candidate.parameterization,
        engine=candidate.engine,
        confidence=candidate.confidence,
        score=candidate.score,
        score_label=candidate.score_label,
        score_factors=candidate.score_factors,
        mitigations=candidate.mitigations,
        entrypoints=[],
        excerpts=[],
        questions=["Truncated — see bundle on disk for full evidence."],
    )


def _replace_bundle(bundle: EvidenceBundle, **changes: Any) -> EvidenceBundle:
    base = bundle.to_jsonable()
    base.update(changes)
    return EvidenceBundle(
        bundle_id=str(base.get("bundle_id") or bundle.bundle_id),
        candidate_id=str(base.get("candidate_id") or bundle.candidate_id),
        stream=str(base.get("stream") or bundle.stream),
        flow_id=base.get("flow_id"),
        cwe=base.get("cwe"),
        source_loc=str(base.get("source_loc") or ""),
        source_name=str(base.get("source_name") or ""),
        sink_name=str(base.get("sink_name") or ""),
        sink_class=str(base.get("sink_class") or ""),
        parameterization=str(base.get("parameterization") or ""),
        engine=str(base.get("engine") or ""),
        confidence=str(base.get("confidence") or ""),
        score=base.get("score"),
        score_label=base.get("score_label"),
        score_factors=[dict(f) for f in base.get("score_factors", []) if isinstance(f, dict)],
        mitigations=[dict(m) for m in base.get("mitigations", []) if isinstance(m, dict)],
        entrypoints=changes.get("entrypoints", bundle.entrypoints),
        excerpts=changes.get("excerpts", bundle.excerpts),
        questions=list(bundle.questions),
    )


def evidence_bundle_from_jsonable(data: dict[str, Any]) -> EvidenceBundle:
    """Rehydrate an evidence bundle written by :func:`write_evidence_bundle`."""
    return EvidenceBundle(
        bundle_id=str(data.get("bundle_id") or ""),
        candidate_id=str(data.get("candidate_id") or ""),
        stream=str(data.get("stream") or ""),
        flow_id=str(data["flow_id"]) if data.get("flow_id") else None,
        cwe=str(data["cwe"]) if data.get("cwe") else None,
        source_loc=str(data.get("source_loc") or ""),
        source_name=str(data.get("source_name") or ""),
        sink_name=str(data.get("sink_name") or ""),
        sink_class=str(data.get("sink_class") or ""),
        parameterization=str(data.get("parameterization") or ""),
        engine=str(data.get("engine") or ""),
        confidence=str(data.get("confidence") or ""),
        score=float(data["score"]) if data.get("score") is not None else None,
        score_label=str(data["score_label"]) if data.get("score_label") else None,
        score_factors=[
            dict(item) for item in data.get("score_factors", []) if isinstance(item, dict)
        ],
        mitigations=[dict(item) for item in data.get("mitigations", []) if isinstance(item, dict)],
        entrypoints=[
            EvidenceEntrypoint(
                kind=str(item.get("kind") or ""),
                signature=str(item.get("signature") or ""),
                file=str(item.get("file") or ""),
                line=int(item.get("line") or 0),
            )
            for item in data.get("entrypoints", [])
            if isinstance(item, dict)
        ],
        excerpts=[
            EvidenceExcerpt(
                file=str(item.get("file") or ""),
                line=int(item.get("line") or 0),
                context_start=int(item.get("context_start") or 0),
                context_end=int(item.get("context_end") or 0),
                code_excerpt=str(item.get("code_excerpt") or ""),
            )
            for item in data.get("excerpts", [])
            if isinstance(item, dict)
        ],
        questions=[str(item) for item in data.get("questions", [])],
    )
