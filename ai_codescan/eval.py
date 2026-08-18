"""Evaluation harness for known-vulnerable scanner targets."""

from __future__ import annotations

import datetime as _dt
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, TypeGuard, get_args

import duckdb
import yaml

from ai_codescan.artifact_id import project_artifact_id
from ai_codescan.config import compute_repo_id
from ai_codescan.engines import joern
from ai_codescan.engines.hybrid import run_hybrid
from ai_codescan.miss_finder import build_miss_candidates
from ai_codescan.prep import run_prep
from ai_codescan.stack_detect import ProjectKind, detect_projects
from ai_codescan.taxonomy.loader import list_classes

EvalStatus = Literal["pass", "partial", "miss", "false_positive", "error"]
MatchStatus = Literal["pass", "partial", "miss"]

_EVAL_STATUSES: frozenset[str] = frozenset(get_args(EvalStatus))
_MATCH_STATUSES: frozenset[str] = frozenset(get_args(MatchStatus))


def _is_eval_status(value: str) -> TypeGuard[EvalStatus]:
    return value in _EVAL_STATUSES


def _is_match_status(value: str) -> TypeGuard[MatchStatus]:
    return value in _MATCH_STATUSES


def _as_eval_status(value: object) -> EvalStatus:
    """Coerce a status read back from JSON onto the literal.

    Result files are external input — a hand-edited or truncated one can carry
    any string. Anything unrecognised is reported as an error rather than
    silently entering the dataclass as an invalid literal.
    """
    text = str(value or "error")
    return text if _is_eval_status(text) else "error"


def _as_match_status(value: object) -> MatchStatus:
    text = str(value or "miss")
    return text if _is_match_status(text) else "miss"


_SUPPORTED_EVAL_ENGINES = {"hybrid", "hybrid-miss", "joern", "miss-finder"}
_MIN_FLOW_STEP_FIELDS = 2


@dataclass(frozen=True, slots=True)
class ExpectedFinding:
    id: str
    cwe: str
    file: str
    source_line: int | None = None
    sink_line: int | None = None
    source_contains: str = ""
    sink_contains: str = ""
    line_tolerance: int = 2
    # Optional per-endpoint file overrides for cross-file flows (source in
    # one file, sink in another — e.g. a controller calling a helper). When
    # empty, the matcher falls back to ``file`` for both endpoints, so
    # single-file manifest entries are unaffected.
    source_file: str = ""
    sink_file: str = ""

    def expected_source_file(self) -> str:
        return self.source_file or self.file

    def expected_sink_file(self) -> str:
        return self.sink_file or self.file


@dataclass(frozen=True, slots=True)
class EvalCase:
    id: str
    target: Path
    language: str
    engine: str
    expected_findings: list[ExpectedFinding]
    allowed_false_positives: list[dict[str, Any]] = field(default_factory=list)
    # Phase 5.1: per-case Joern sink extensions. The harness writes these
    # into the repo cache as ``aics-joern-extension-packs.json`` before
    # Joern runs, so the eval target doesn't need to ship its own JSON
    # file. Each entry follows the JoernExtensionEntry schema
    # (language/cwe/sink_class/pattern + optional receiver_regex).
    joern_extensions: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class FlowRecord:
    flow_id: str
    cwe: str
    source_file: str
    source_line: int
    sink_file: str
    sink_line: int
    source_name: str
    sink_name: str
    engine: str = ""
    flow_type: str = "dataflow"


@dataclass(frozen=True, slots=True)
class FindingMatch:
    expected_id: str
    status: MatchStatus
    flow_id: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class EvalResult:
    case_id: str
    scanner: str
    status: EvalStatus
    matches: list[FindingMatch]
    false_positives: list[FlowRecord]
    duration_sec: float
    error: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "scanner": self.scanner,
            "status": self.status,
            "matches": [asdict(m) for m in self.matches],
            "false_positives": [asdict(fp) for fp in self.false_positives],
            "duration_sec": round(self.duration_sec, 3),
            "error": self.error,
            "warnings": self.warnings,
        }


@dataclass(frozen=True, slots=True)
class EvalComparison:
    case_id: str
    ai_status: str
    ghost_status: str
    delta: str
    ai_warnings: list[str] = field(default_factory=list)
    ghost_warnings: list[str] = field(default_factory=list)

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


def _as_expected(raw: dict[str, Any]) -> ExpectedFinding:
    for key in ("id", "cwe", "file"):
        if key not in raw:
            raise ValueError(f"expected finding is missing required field: {key}")
    return ExpectedFinding(
        id=str(raw["id"]),
        cwe=str(raw["cwe"]),
        file=str(raw["file"]),
        source_line=int(raw["source_line"]) if raw.get("source_line") is not None else None,
        sink_line=int(raw["sink_line"]) if raw.get("sink_line") is not None else None,
        source_contains=str(raw.get("source_contains") or ""),
        sink_contains=str(raw.get("sink_contains") or ""),
        line_tolerance=int(raw.get("line_tolerance", 2)),
        source_file=str(raw.get("source_file") or ""),
        sink_file=str(raw.get("sink_file") or ""),
    )


def load_eval_cases(path: Path) -> list[EvalCase]:  # noqa: PLR0912 - manifest validation needs the branches
    """Load eval cases from a manifest file or directory containing manifest.yml."""
    manifest = path / "manifest.yml" if path.is_dir() else path
    if not manifest.is_file():
        raise ValueError(f"eval manifest does not exist: {manifest}")
    data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    root = manifest.parent
    cases: list[EvalCase] = []
    raw_cases = data.get("cases", [])
    if not isinstance(raw_cases, list):
        raise ValueError("eval manifest field `cases` must be a list")
    for raw in raw_cases:
        if not isinstance(raw, dict):
            raise ValueError("eval case entries must be objects")
        for key in ("id", "target", "language"):
            if key not in raw:
                raise ValueError(f"eval case is missing required field: {key}")
        target = Path(str(raw["target"]))
        if not target.is_absolute():
            target = root / target
        if not target.exists():
            raise ValueError(f"eval target does not exist: {target}")
        local_meta_path = target / "eval.yaml"
        merged = dict(raw)
        if local_meta_path.is_file():
            local_meta = yaml.safe_load(local_meta_path.read_text(encoding="utf-8")) or {}
            if not isinstance(local_meta, dict):
                raise ValueError(f"target eval.yaml must be an object: {local_meta_path}")
            merged.update(local_meta)
            merged["target"] = str(raw["target"])
        expected_raw = merged.get("expected_findings", [])
        if not isinstance(expected_raw, list):
            raise ValueError(f"expected_findings must be a list for eval case {merged['id']}")
        allowed_raw = merged.get("allowed_false_positives", [])
        if not isinstance(allowed_raw, list):
            raise ValueError(f"allowed_false_positives must be a list for eval case {merged['id']}")
        joern_ext_raw = merged.get("joern_extensions", [])
        if not isinstance(joern_ext_raw, list):
            raise ValueError(f"joern_extensions must be a list for eval case {merged['id']}")
        cases.append(
            EvalCase(
                id=str(merged["id"]),
                target=target,
                language=str(merged["language"]),
                engine=str(merged.get("engine") or data.get("default_engine") or "hybrid"),
                expected_findings=[_as_expected(item) for item in expected_raw],
                allowed_false_positives=[
                    dict(item) for item in allowed_raw if isinstance(item, dict)
                ],
                joern_extensions=[dict(item) for item in joern_ext_raw if isinstance(item, dict)],
            )
        )
    return cases


def _flow_from_joern(raw: dict[str, Any]) -> FlowRecord:
    return FlowRecord(
        flow_id=str(raw.get("fid") or ""),
        cwe=str(raw.get("cwe") or ""),
        source_file=str(raw.get("source_file") or ""),
        source_line=int(raw.get("source_line") or 0),
        sink_file=str(raw.get("sink_file") or ""),
        sink_line=int(raw.get("sink_line") or 0),
        source_name=str(raw.get("source_name") or ""),
        sink_name=str(raw.get("sink_name") or ""),
        engine="joern",
    )


def _flow_from_db_row(row: tuple[Any, ...]) -> FlowRecord:
    fid, cwe, engine, steps_json, source_name, sink_name, flow_type = row
    source_file = ""
    source_line = 0
    sink_file = ""
    sink_line = 0
    try:
        steps = json.loads(steps_json or "[]")
    except json.JSONDecodeError:
        steps = []
    if steps:
        first = steps[0]
        if isinstance(first, list) and len(first) >= _MIN_FLOW_STEP_FIELDS:
            source_file = str(first[0])
            source_line = int(first[1] or 0)
        last = steps[-1]
        if isinstance(last, list) and len(last) >= _MIN_FLOW_STEP_FIELDS:
            sink_file = str(last[0])
            sink_line = int(last[1] or 0)
    return FlowRecord(
        flow_id=str(fid or ""),
        cwe=str(cwe or ""),
        source_file=source_file,
        source_line=source_line,
        sink_file=sink_file,
        sink_line=sink_line,
        source_name=str(source_name or ""),
        sink_name=str(sink_name or ""),
        engine=str(engine or ""),
        flow_type=str(flow_type or "dataflow"),
    )


def flows_from_db(db_path: Path) -> list[FlowRecord]:
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        rows = conn.execute(
            """
            SELECT f.fid, f.cwe, f.engine, f.steps_json, s.key, k.lib,
                   COALESCE(m.flow_type, 'dataflow')
            FROM flows f
            LEFT JOIN taint_sources s ON s.tid = f.tid
            LEFT JOIN taint_sinks k ON k.sid = f.sid
            LEFT JOIN flow_metadata m ON m.fid = f.fid
            ORDER BY f.fid
            """
        ).fetchall()
    finally:
        conn.close()
    return [_flow_from_db_row(row) for row in rows]


def miss_candidates_from_db(db_path: Path) -> list[FlowRecord]:
    """Return miss-finder candidates as eval-comparable records."""
    conn = duckdb.connect(str(db_path))
    try:
        candidates = build_miss_candidates(conn, source_root=db_path.parent / "source")
    finally:
        conn.close()
    return [
        FlowRecord(
            flow_id=str(candidate.get("id") or ""),
            cwe=str(candidate.get("cwe") or ""),
            source_file=str(candidate.get("file") or ""),
            source_line=int(candidate.get("line") or 0),
            sink_file=str(candidate.get("file") or ""),
            sink_line=int(candidate.get("line") or 0),
            source_name=str(candidate.get("name") or ""),
            sink_name=str(candidate.get("heuristic") or candidate.get("concern") or ""),
            engine="miss-finder",
        )
        for candidate in candidates
    ]


def _hybrid_project_roots(snapshot_root: Path) -> list[tuple[Path, str, str]]:
    roots: list[tuple[Path, str, str]] = []
    for project in detect_projects(snapshot_root):
        if project.kind is ProjectKind.NODE:
            language = "javascript"
        elif project.kind is ProjectKind.PYTHON:
            language = "python"
        elif project.kind is ProjectKind.JAVA:
            project_dir = snapshot_root / project.base_path
            java_count = sum(1 for _ in project_dir.rglob("*.java"))
            kotlin_count = sum(1 for p in project_dir.rglob("*") if p.suffix in {".kt", ".kts"})
            language = "kotlin" if kotlin_count > java_count else "java"
        elif project.kind is ProjectKind.GO:
            language = "go"
        elif project.kind is ProjectKind.RUBY:
            language = "ruby"
        elif project.kind is ProjectKind.PHP:
            language = "php"
        elif project.kind is ProjectKind.CSHARP:
            language = "csharp"
        else:
            continue
        project_id = project_artifact_id(project.name, project.base_path)
        roots.append((snapshot_root / project.base_path, project_id, language))
    return roots


def _run_hybrid_case(
    case: EvalCase,
    *,
    cache_root: Path,
    include_miss_candidates: bool = False,
) -> list[FlowRecord]:
    repo_dir = cache_root / compute_repo_id(case.target)
    db_path = repo_dir / "index.duckdb"
    if db_path.exists():
        db_path.unlink()
    snap, db_path = run_prep(
        case.target,
        cache_root=cache_root,
        bug_classes=list_classes(),
        engine="codeql",
        quiet=True,
        force=True,
    )
    # Write the Joern extension JSON into the repo cache from the
    # manifest's ``joern_extensions`` field. The Phase 5 file-copy
    # fallback (sidecar JSON shipped in the target dir) was removed in
    # Phase 5.1 after migrating the only consumer to the manifest field;
    # no eval target ships a sidecar anymore.
    if case.joern_extensions:
        (repo_dir / "aics-joern-extension-packs.json").write_text(
            json.dumps({"sinks": case.joern_extensions}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    roots = _hybrid_project_roots(snap.snapshot_dir)
    run_hybrid(
        roots,
        snapshot_root=snap.snapshot_dir,
        repo_dir=repo_dir,
        db_path=db_path,
    )
    flows = flows_from_db(db_path)
    if include_miss_candidates:
        flows.extend(miss_candidates_from_db(db_path))
    return flows


def _run_miss_finder_case(case: EvalCase, *, cache_root: Path) -> list[FlowRecord]:
    """Exercise semantic candidate generation without external SAST engines."""
    repo_dir = cache_root / compute_repo_id(case.target)
    db_path = repo_dir / "index.duckdb"
    if db_path.exists():
        db_path.unlink()
    _snapshot, db_path = run_prep(
        case.target,
        cache_root=cache_root,
        bug_classes=list_classes(),
        engine="none",
        quiet=True,
        force=True,
    )
    return miss_candidates_from_db(db_path)


def _run_joern_case(case: EvalCase, *, cache_root: Path) -> list[FlowRecord]:
    jsonl = joern.run_joern(
        case.target,
        cache_dir=cache_root / "eval-joern",
        project_id=case.id,
        language=case.language,
    )
    return [_flow_from_joern(item) for item in joern.parse_flows(jsonl)]


def _path_matches(actual: str, expected: str) -> bool:
    actual_norm = actual.replace("\\", "/")
    expected_norm = expected.replace("\\", "/").lstrip("./")
    return actual_norm.endswith(expected_norm)


def _line_matches(actual: int, expected: int | None, tolerance: int) -> bool:
    if expected is None:
        return True
    return abs(actual - expected) <= tolerance


def _contains(actual: str, expected: str) -> bool:
    return not expected or expected.lower() in actual.lower()


def _full_match(flow: FlowRecord, expected: ExpectedFinding) -> bool:
    return (
        flow.cwe == expected.cwe
        and _path_matches(flow.source_file, expected.expected_source_file())
        and _path_matches(flow.sink_file, expected.expected_sink_file())
        and _line_matches(flow.source_line, expected.source_line, expected.line_tolerance)
        and _line_matches(flow.sink_line, expected.sink_line, expected.line_tolerance)
        and _contains(flow.source_name, expected.source_contains)
        and _contains(flow.sink_name, expected.sink_contains)
    )


def _partial_match(flow: FlowRecord, expected: ExpectedFinding) -> bool:
    if flow.cwe != expected.cwe:
        return False
    path_matches = _path_matches(
        flow.source_file, expected.expected_source_file()
    ) or _path_matches(flow.sink_file, expected.expected_sink_file())
    if not path_matches:
        return False
    source_signal = _line_matches(
        flow.source_line,
        expected.source_line,
        expected.line_tolerance,
    ) or (expected.source_contains and _contains(flow.source_name, expected.source_contains))
    sink_signal = _line_matches(flow.sink_line, expected.sink_line, expected.line_tolerance) or (
        expected.sink_contains and _contains(flow.sink_name, expected.sink_contains)
    )
    return bool(source_signal or sink_signal)


def _allowed_false_positive(flow: FlowRecord, allowed: list[dict[str, Any]]) -> bool:
    for item in allowed:
        if item.get("cwe") and flow.cwe != str(item["cwe"]):
            continue
        if item.get("file") and not (
            _path_matches(flow.source_file, str(item["file"]))
            or _path_matches(flow.sink_file, str(item["file"]))
        ):
            continue
        if item.get("sink_contains") and not _contains(flow.sink_name, str(item["sink_contains"])):
            continue
        return True
    return False


def score_flows(flows: list[FlowRecord], case: EvalCase) -> EvalResult:
    """Classify scanner flows against one eval case's ground truth."""
    warnings = [] if flows else ["scanner completed but produced no flows"]
    matches: list[FindingMatch] = []
    matched_flow_ids: set[str] = set()
    for expected in case.expected_findings:
        full = next((flow for flow in flows if _full_match(flow, expected)), None)
        if full is not None:
            matched_flow_ids.add(full.flow_id)
            matches.append(
                FindingMatch(expected.id, "pass", full.flow_id, "source and sink matched")
            )
            continue
        partial = next((flow for flow in flows if _partial_match(flow, expected)), None)
        if partial is not None:
            matched_flow_ids.add(partial.flow_id)
            matches.append(
                FindingMatch(
                    expected.id,
                    "partial",
                    partial.flow_id,
                    "CWE matched but source/sink precision was incomplete",
                )
            )
            continue
        matches.append(FindingMatch(expected.id, "miss", None, "no matching flow"))

    false_positives = []
    for flow in flows:
        # Co-location-fallback flows are by design weak evidence (proximity,
        # not data-flow proof) and are heavily demoted by scoring. They appear
        # in the candidate audit so reviewers can see them, but they are NOT
        # counted as scanner false positives in eval — they're acceptable
        # noise under the recall-first stance (§8, Invariant 6). Use a real
        # data-flow flow if you want eval to catch a regression.
        if flow.flow_type == "co-location":
            continue
        if flow.flow_id in matched_flow_ids:
            continue
        if any(
            _full_match(flow, expected) or _partial_match(flow, expected)
            for expected in case.expected_findings
        ):
            continue
        if _allowed_false_positive(flow, case.allowed_false_positives):
            continue
        false_positives.append(flow)

    if any(match.status == "miss" for match in matches):
        status: EvalStatus = "miss"
    elif false_positives:
        status = "false_positive"
    elif any(match.status == "partial" for match in matches):
        status = "partial"
    else:
        status = "pass"

    return EvalResult(
        case_id=case.id,
        scanner="ai-codescan",
        status=status,
        matches=matches,
        false_positives=false_positives,
        duration_sec=0.0,
        warnings=warnings,
    )


def run_ai_codescan_case(
    case: EvalCase,
    *,
    cache_root: Path,
    engine: str | None = None,
) -> EvalResult:
    """Run the deterministic scanner path for one eval case.

    The default ``hybrid`` engine runs the scanner's normal prep/hybrid path
    and scores final DuckDB flows. ``joern`` remains available for narrow
    engine-model regression tests.
    """
    selected_engine = engine or case.engine
    started = time.monotonic()
    try:
        if selected_engine not in _SUPPORTED_EVAL_ENGINES:
            raise ValueError(
                f"eval engine {selected_engine!r} is not supported; "
                f"choose one of {', '.join(sorted(_SUPPORTED_EVAL_ENGINES))}"
            )
        if selected_engine in {"hybrid", "hybrid-miss"}:
            flows = _run_hybrid_case(
                case,
                cache_root=cache_root,
                include_miss_candidates=selected_engine == "hybrid-miss",
            )
        elif selected_engine == "miss-finder":
            flows = _run_miss_finder_case(case, cache_root=cache_root)
        else:
            flows = _run_joern_case(case, cache_root=cache_root)
        result = score_flows(flows, case)
        return EvalResult(
            case_id=result.case_id,
            scanner=result.scanner,
            status=result.status,
            matches=result.matches,
            false_positives=result.false_positives,
            duration_sec=time.monotonic() - started,
            warnings=result.warnings,
        )
    except Exception as exc:  # noqa: BLE001 - eval should record per-case errors
        return EvalResult(
            case_id=case.id,
            scanner="ai-codescan",
            status="error",
            matches=[],
            false_positives=[],
            duration_sec=time.monotonic() - started,
            error=str(exc),
            warnings=[],
        )


def write_eval_outputs(results: list[EvalResult], *, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"
    with results_path.open("w", encoding="utf-8") as f:
        for result in results:
            f.write(json.dumps(result.to_jsonable(), sort_keys=True))
            f.write("\n")

    counts: dict[str, int] = {
        key: 0 for key in ("pass", "partial", "miss", "false_positive", "error")
    }
    for result in results:
        counts[result.status] += 1
    warnings_count = sum(len(result.warnings) for result in results)
    summary = {
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        "cases": len(results),
        "counts": counts,
        "warnings": warnings_count,
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    report_lines = [
        "# Eval Summary",
        "",
        f"- Cases: {len(results)}",
        f"- Pass: {counts['pass']}",
        f"- Partial: {counts['partial']}",
        f"- Miss: {counts['miss']}",
        f"- False positive: {counts['false_positive']}",
        f"- Error: {counts['error']}",
        f"- Warnings: {warnings_count}",
        "",
        "| Case | Status | Warnings | Error |",
        "| --- | --- | --- | --- |",
    ]
    for result in results:
        warnings = "<br>".join(result.warnings)
        report_lines.append(
            f"| `{result.case_id}` | {result.status} | {warnings} | {result.error} |"
        )
    (out_dir / "report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    trend_rows = []
    for result in results:
        trend_rows.append(
            {
                "case_id": result.case_id,
                "status": result.status,
                "true_positive": sum(1 for match in result.matches if match.status == "pass"),
                "partial": sum(1 for match in result.matches if match.status == "partial"),
                "false_negative": sum(1 for match in result.matches if match.status == "miss"),
                "false_positive": len(result.false_positives),
                "runtime_sec": round(result.duration_sec, 3),
                "llm_reviewed_candidates": 0,
                "warnings": len(result.warnings),
            }
        )
    trend_path = out_dir / "trend.jsonl"
    with trend_path.open("w", encoding="utf-8") as f:
        for row in trend_rows:
            f.write(json.dumps(row, sort_keys=True))
            f.write("\n")
    trend_lines = [
        "# Eval Trend Rows",
        "",
        "| Case | Status | TP | Partial | FN | FP | Runtime | LLM Reviewed | Warnings |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in trend_rows:
        trend_lines.append(
            f"| `{row['case_id']}` | {row['status']} | {row['true_positive']} | "
            f"{row['partial']} | {row['false_negative']} | {row['false_positive']} | "
            f"{row['runtime_sec']} | {row['llm_reviewed_candidates']} | {row['warnings']} |"
        )
    (out_dir / "trend.md").write_text("\n".join(trend_lines) + "\n", encoding="utf-8")
    return results_path


def _result_from_raw(raw: dict[str, Any], *, scanner: str) -> EvalResult:
    matches = [
        FindingMatch(
            expected_id=str(item.get("expected_id") or item.get("id") or ""),
            status=_as_match_status(item.get("status")),
            flow_id=str(item["flow_id"]) if item.get("flow_id") is not None else None,
            reason=str(item.get("reason") or ""),
        )
        for item in raw.get("matches", [])
        if isinstance(item, dict)
    ]
    false_positives = [
        FlowRecord(
            flow_id=str(item.get("flow_id") or ""),
            cwe=str(item.get("cwe") or ""),
            source_file=str(item.get("source_file") or ""),
            source_line=int(item.get("source_line") or 0),
            sink_file=str(item.get("sink_file") or ""),
            sink_line=int(item.get("sink_line") or 0),
            source_name=str(item.get("source_name") or ""),
            sink_name=str(item.get("sink_name") or ""),
            engine=str(item.get("engine") or scanner),
        )
        for item in raw.get("false_positives", [])
        if isinstance(item, dict)
    ]
    return EvalResult(
        case_id=str(raw.get("case_id") or raw.get("case") or raw.get("id") or ""),
        scanner=str(raw.get("scanner") or scanner),
        status=_as_eval_status(raw.get("status")),
        matches=matches,
        false_positives=false_positives,
        duration_sec=float(raw.get("duration_sec") or 0.0),
        error=str(raw.get("error") or ""),
        warnings=[str(item) for item in raw.get("warnings", [])],
    )


def load_eval_results(path: Path, *, scanner: str) -> list[EvalResult]:
    """Load eval result JSON/JSONL for ai-codescan or imported Ghost output."""
    if path.suffix == ".jsonl":
        rows = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            rows = data.get("results", data.get("cases", []))
            if not isinstance(rows, list):
                rows = [data]
        elif isinstance(data, list):
            rows = data
        else:
            rows = []
    return [_result_from_raw(row, scanner=scanner) for row in rows if isinstance(row, dict)]


def _status_rank(status: str) -> int:
    return {
        "pass": 4,
        "partial": 3,
        "false_positive": 2,
        "miss": 1,
        "error": 0,
    }.get(status, 0)


def compare_eval_results(
    ai_results: list[EvalResult],
    ghost_results: list[EvalResult],
) -> list[EvalComparison]:
    ai_by_case = {result.case_id: result for result in ai_results}
    ghost_by_case = {result.case_id: result for result in ghost_results}
    comparisons: list[EvalComparison] = []
    for case_id in sorted(ai_by_case.keys() | ghost_by_case.keys()):
        ai = ai_by_case.get(case_id)
        ghost = ghost_by_case.get(case_id)
        ai_status = ai.status if ai else "missing"
        ghost_status = ghost.status if ghost else "missing"
        if ai is None:
            delta = "ghost-only"
        elif ghost is None:
            delta = "ai-only"
        elif ai_status == ghost_status:
            delta = "same"
        elif _status_rank(ai_status) > _status_rank(ghost_status):
            delta = "ai-better"
        else:
            delta = "ghost-better"
        comparisons.append(
            EvalComparison(
                case_id=case_id,
                ai_status=ai_status,
                ghost_status=ghost_status,
                delta=delta,
                ai_warnings=ai.warnings if ai else [],
                ghost_warnings=ghost.warnings if ghost else [],
            )
        )
    return comparisons


def write_eval_comparison(
    comparisons: list[EvalComparison],
    *,
    out_dir: Path,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl = out_dir / "comparison.jsonl"
    with jsonl.open("w", encoding="utf-8") as f:
        for comparison in comparisons:
            f.write(json.dumps(comparison.to_jsonable(), sort_keys=True))
            f.write("\n")
    lines = [
        "# Eval Comparison",
        "",
        "| Case | ai-codescan | Ghost | Delta |",
        "| --- | --- | --- | --- |",
    ]
    for comparison in comparisons:
        lines.append(
            f"| `{comparison.case_id}` | {comparison.ai_status} | "
            f"{comparison.ghost_status} | {comparison.delta} |"
        )
    (out_dir / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return jsonl
