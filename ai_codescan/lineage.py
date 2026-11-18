"""Run-scoped candidate lineage artifacts."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai_codescan.findings.model import parse_finding
from ai_codescan.findings.queue import parse_queue
from ai_codescan.gate import Nomination, parse_nominations
from ai_codescan.review_verdicts import parse_review_verdict

_REGISTRY_NAME = "candidate_registry.jsonl"
_MISS_RESULTS_NAME = "miss-review-results.jsonl"
_REPORT_MANIFEST_NAME = "report-manifest.jsonl"
_MIN_LOG_CELLS = 2
_DERIVED_NAMES = (
    _REGISTRY_NAME,
    _MISS_RESULTS_NAME,
    _REPORT_MANIFEST_NAME,
    "candidate-lineage.jsonl",
    "candidate-lineage.md",
)


@dataclass(frozen=True, slots=True)
class _LineageContext:
    nominations: dict[str, Nomination]
    queued_candidates: set[str]
    findings: dict[str, dict[str, str]]
    miss_results: dict[str, dict[str, Any]]
    validation: dict[str, str]
    reports: dict[str, str]


def reset_candidate_lineage(run_dir: Path) -> None:
    """Remove lineage artifacts before a new nomination generation."""
    for name in _DERIVED_NAMES:
        (run_dir / name).unlink(missing_ok=True)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(text)
        temporary_path = Path(handle.name)
    os.replace(temporary_path, path)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [
        value
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and isinstance((value := json.loads(line)), dict)
    ]


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    _atomic_write(path, text)


def record_candidates(
    run_dir: Path,
    *,
    run_id: str,
    candidates: Sequence[dict[str, Any]],
    selected_candidate_ids: set[str],
    origin: str,
) -> Path:
    """Store the complete candidate set and its first review disposition."""
    registry_path = run_dir / _REGISTRY_NAME
    existing = _read_jsonl(registry_path)
    rows = [row for row in existing if str(row.get("origin") or "") != origin]
    for candidate in candidates:
        candidate_id = str(candidate.get("id") or "")
        if not candidate_id:
            raise ValueError(f"candidate from {origin} has no id")
        selected = candidate_id in selected_candidate_ids
        skip_reason = str(candidate.get("skip_reason") or "")
        if not selected and not skip_reason:
            skip_reason = "review-limit"
        rows.append(
            {
                **candidate,
                "run_id": run_id,
                "candidate_id": candidate_id,
                "origin": origin,
                "initial_disposition": "queued" if selected else "skipped",
                "skip_reason": skip_reason,
            }
        )
    rows.sort(key=lambda row: (str(row.get("origin") or ""), str(row["candidate_id"])))
    _write_jsonl(registry_path, rows)
    return registry_path


def write_miss_review_results(run_dir: Path, reviews: Sequence[Any]) -> Path:
    path = run_dir / _MISS_RESULTS_NAME
    _write_jsonl(path, (review.to_jsonable() for review in reviews))
    return path


def write_report_manifest(
    run_dir: Path,
    findings: Sequence[Any],
    report_paths: Sequence[Path],
) -> Path:
    if len(findings) != len(report_paths):
        raise ValueError("the report manifest requires one path for each finding")
    path = run_dir / _REPORT_MANIFEST_NAME
    rows = [
        {"finding_id": finding.finding_id, "report_path": str(report_path)}
        for finding, report_path in zip(findings, report_paths, strict=True)
    ]
    _write_jsonl(path, rows)
    return path


def _load_nominations(run_dir: Path) -> dict[str, Nomination]:
    path = run_dir / "nominations.md"
    if not path.is_file():
        return {}
    return {
        nomination.candidate_id: nomination
        for nomination in parse_nominations(path.read_text(encoding="utf-8"))
        if nomination.candidate_id
    }


def _load_queue(run_dir: Path) -> set[str]:
    path = run_dir / "findings_queue.md"
    if not path.is_file():
        return set()
    return {
        item.candidate_id or item.nomination_id
        for item in parse_queue(path.read_text(encoding="utf-8"))
    }


def _load_findings(run_dir: Path) -> dict[str, dict[str, str]]:
    findings: dict[str, dict[str, str]] = {}
    for path in sorted((run_dir / "findings").glob("*.md")):
        markdown = path.read_text(encoding="utf-8")
        if not markdown.startswith("---\n"):
            continue
        finding = parse_finding(markdown)
        verdict = parse_review_verdict(path)
        candidate_id = verdict.candidate_id if verdict else finding.nomination_id
        findings[candidate_id] = {
            "finding_id": finding.finding_id,
            "finding_status": finding.status,
            "analysis_verdict": verdict.verdict if verdict else "",
            "analysis_confidence": verdict.confidence if verdict else "",
            "finding_title": finding.title,
        }
    return findings


def _load_validation(run_dir: Path) -> dict[str, str]:
    path = run_dir / "validation_log.md"
    if not path.is_file():
        return {}
    statuses: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= _MIN_LOG_CELLS and cells[0].startswith("F-"):
            statuses[cells[0]] = cells[1]
    return statuses


def _finding_outcome(finding: dict[str, str], report_path: str) -> tuple[str, str]:
    status = finding["finding_status"]
    if status == "verified" and report_path:
        return "reported", "verified-and-reported"
    if status == "verified":
        return "verified", "report-not-produced"
    if status == "rejected":
        reason = finding["analysis_verdict"] or "analysis-rejected"
        return "rejected", reason
    if status == "poc_inconclusive":
        return "inconclusive", "validation-inconclusive"
    validation_status = finding.get("validation_status", "")
    if validation_status.startswith(("unsupported-", "sandbox-unavailable")):
        return "inconclusive", validation_status
    return "unverified", finding["analysis_verdict"] or "validation-not-complete"


def _main_outcome(
    row: dict[str, Any],
    nomination: Nomination | None,
    queued: bool,
    finding: dict[str, str] | None,
    report_path: str,
) -> tuple[str, str]:
    outcome: tuple[str, str]
    if row["initial_disposition"] == "skipped":
        outcome = ("skipped", str(row.get("skip_reason") or "not-selected"))
    elif nomination is None:
        outcome = ("not-nominated", "nomination-not-produced")
    elif nomination.decision == "n":
        outcome = ("rejected", "gate-rejected")
    elif nomination.decision != "y":
        outcome = ("pending", "gate-decision-pending")
    elif not queued:
        outcome = ("not-selected", "analysis-not-selected")
    elif finding is None:
        outcome = ("not-analyzed", "analysis-output-missing")
    else:
        outcome = _finding_outcome(finding, report_path)
    return outcome


def _miss_outcome(
    row: dict[str, Any],
    review: dict[str, Any] | None,
    finding: dict[str, str] | None,
    report_path: str,
) -> tuple[str, str]:
    outcome: tuple[str, str]
    if row["initial_disposition"] == "skipped":
        outcome = ("not-selected", str(row.get("skip_reason") or "review-limit"))
    elif review is None:
        outcome = ("not-analyzed", "miss-review-output-missing")
    elif finding is not None:
        outcome = _finding_outcome(finding, report_path)
    else:
        classification = str(review.get("classification") or "")
        state_by_classification = {
            "covered-by-static": "covered",
            "false-positive": "rejected",
            "needs-human-context": "inconclusive",
        }
        outcome = (
            state_by_classification.get(classification, "reviewed"),
            classification or "miss-review-complete",
        )
    return outcome


def _lineage_record(
    row: dict[str, Any],
    context: _LineageContext,
) -> dict[str, Any]:
    candidate_id = str(row["candidate_id"])
    nomination = context.nominations.get(candidate_id)
    finding = context.findings.get(candidate_id)
    finding_id = finding["finding_id"] if finding else ""
    validation_status = context.validation.get(finding_id, "")
    if finding is not None:
        finding = {**finding, "validation_status": validation_status}
    report_path = context.reports.get(finding_id, "")
    analysis_selected = (
        row["initial_disposition"] == "queued"
        if row["origin"] == "miss-finder"
        else candidate_id in context.queued_candidates
    )
    if row["origin"] == "miss-finder":
        final_state, reason = _miss_outcome(
            row, context.miss_results.get(candidate_id), finding, report_path
        )
    else:
        final_state, reason = _main_outcome(
            row,
            nomination,
            candidate_id in context.queued_candidates,
            finding,
            report_path,
        )
    return {
        "run_id": row["run_id"],
        "candidate_id": candidate_id,
        "origin": row["origin"],
        "stream": row.get("stream", ""),
        "source_location": row.get("source_loc")
        or f"{row.get('file', '')}:{row.get('line', '')}".rstrip(":"),
        "score": row.get("score"),
        "score_label": row.get("score_label", ""),
        "skip_reason": row.get("skip_reason", ""),
        "nomination_id": nomination.nomination_id if nomination else "",
        "nomination_decision": nomination.decision if nomination else "",
        "analysis_selected": analysis_selected,
        "finding_id": finding_id,
        "analysis_verdict": finding["analysis_verdict"] if finding else "",
        "analysis_confidence": finding["analysis_confidence"] if finding else "",
        "finding_status": finding["finding_status"] if finding else "",
        "validation_status": validation_status,
        "report_path": report_path,
        "final_state": final_state,
        "reason": reason,
    }


def _render_markdown(records: Sequence[dict[str, Any]]) -> str:
    lines = [
        "# Candidate lineage",
        "",
        "This report follows each run candidate through nomination, analysis, "
        "validation, and reporting.",
        "",
        "| candidate | origin | nomination | finding | final state | reason |",
        "|---|---|---|---|---|---|",
    ]
    for record in records:
        cells = [
            record["candidate_id"],
            record["origin"],
            record["nomination_id"] or "-",
            record["finding_id"] or "-",
            record["final_state"],
            record["reason"],
        ]
        escaped = [str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells]
        lines.append("| " + " | ".join(escaped) + " |")
    return "\n".join(lines) + "\n"


def refresh_candidate_lineage(run_dir: Path) -> tuple[Path, Path] | None:
    """Rebuild the machine and human lineage views from run artifacts."""
    registry = _read_jsonl(run_dir / _REGISTRY_NAME)
    if not registry:
        return None
    miss_results = {
        str(row.get("candidate_id") or ""): row for row in _read_jsonl(run_dir / _MISS_RESULTS_NAME)
    }
    reports = {
        str(row.get("finding_id") or ""): str(row.get("report_path") or "")
        for row in _read_jsonl(run_dir / _REPORT_MANIFEST_NAME)
    }
    context = _LineageContext(
        nominations=_load_nominations(run_dir),
        queued_candidates=_load_queue(run_dir),
        findings=_load_findings(run_dir),
        miss_results=miss_results,
        validation=_load_validation(run_dir),
        reports=reports,
    )
    records = [_lineage_record(row, context) for row in registry]
    json_path = run_dir / "candidate-lineage.jsonl"
    markdown_path = run_dir / "candidate-lineage.md"
    _write_jsonl(json_path, records)
    _atomic_write(markdown_path, _render_markdown(records))
    return json_path, markdown_path
