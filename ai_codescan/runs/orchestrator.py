"""End-to-end pipeline driver.

Composes ``prep → nominate → gate-1 → analyze → gate-2 → validate →
gate-3 → report`` into a single command. Persists progress at
``<cache>/<repo_id>/run.state.json`` so re-running the same target picks
up after the last completed stage.

Interactive interrupts (suppressed by ``--yes``):

* an LLM provider/model wasn't supplied on the CLI;
* a stage produced zero actionable artefacts;
* a stage exited non-zero with rate-limit / auth keywords in stderr;
* every HITL gate (``gate-1``, ``gate-2``, ``gate-3``).

Each interrupt rings the terminal bell and tells the user which CLI
flag would skip the prompt next time.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from ai_codescan.cache_state import scan_db_stage
from ai_codescan.engines.semgrep import configured_rules_roots
from ai_codescan.findings.model import parse_finding
from ai_codescan.findings.queue import parse_queue, render_queue
from ai_codescan.gate import parse_nominations
from ai_codescan.manifest import build_manifest
from ai_codescan.snapshot import git_worktree_is_dirty

PIPELINE_STAGES: tuple[str, ...] = (
    "prep",
    "nominate",
    "gate-1",
    "analyze",
    "gate-2",
    "validate",
    "gate-3",
    "report",
)
"""Default pipeline order. ``--phases`` slices this; ``--from``/``--to``
trim either end."""

_RATE_LIMIT_KEYWORDS: tuple[str, ...] = (
    "rate limit",
    "rate-limit",
    "rate_limit",
    "too many requests",
    " 429",
    "quota exceeded",
    "unauthenticated",
    "unauthorized",
    " 401",
    " 403",
    "invalid api key",
    "api key",
    "credentials",
    "please log in",
    "please login",
    "not logged in",
)


@dataclass(slots=True)
class OrchestratorState:
    """Persistent pipeline state at ``<cache>/<repo_id>/run.state.json``.

    Tracks which stages already completed and the user's most recent
    decisions for each prompt so re-running the wrapper after Ctrl-C is
    idempotent.
    """

    repo_id: str
    target: str
    phases: list[str]
    completed: list[str] = field(default_factory=list)
    stage_fingerprints: dict[str, str] = field(default_factory=dict)
    last_error: str | None = None
    decisions: dict[str, str] = field(default_factory=dict)


def state_path(cache_root: Path, repo_id: str) -> Path:
    return cache_root / repo_id / "run.state.json"


def load_state(cache_root: Path, repo_id: str) -> OrchestratorState | None:
    p = state_path(cache_root, repo_id)
    if not p.is_file():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    return OrchestratorState(
        repo_id=str(data["repo_id"]),
        target=str(data["target"]),
        phases=list(data.get("phases", PIPELINE_STAGES)),
        completed=list(data.get("completed", [])),
        stage_fingerprints=dict(data.get("stage_fingerprints", {})),
        last_error=data.get("last_error"),
        decisions=dict(data.get("decisions", {})),
    )


def save_state(cache_root: Path, state: OrchestratorState) -> None:
    p = state_path(cache_root, state.repo_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "repo_id": state.repo_id,
        "target": state.target,
        "phases": state.phases,
        "completed": state.completed,
        "stage_fingerprints": state.stage_fingerprints,
        "last_error": state.last_error,
        "decisions": state.decisions,
    }
    p.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
# Failure detection
# ---------------------------------------------------------------------------


def detect_rate_limit_or_auth(stderr: str) -> bool:
    """Best-effort match against well-known LLM/auth failure phrasings."""
    low = f" {stderr.lower()} "
    return any(kw in low for kw in _RATE_LIMIT_KEYWORDS)


# ---------------------------------------------------------------------------
# Completion fingerprints
# ---------------------------------------------------------------------------


_SCANNER_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_SCANNER_FILE_SUFFIXES = frozenset(
    {
        ".css",
        ".html",
        ".js",
        ".json",
        ".md",
        ".mjs",
        ".py",
        ".pyi",
        ".ql",
        ".qll",
        ".sc",
        ".sh",
        ".yaml",
        ".yml",
    }
)
_SCANNER_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "eval-targets",
        "fixtures",
        "generated",
        "node_modules",
        "out",
        "site-packages",
        "target",
        "tests",
        "vendor",
        "venv",
    }
)
_REPO_SCANNER_CONFIG_FILES = (
    "aics-codeql-extension-packs.json",
    "aics-enabled-packs.json",
    "aics-joern-extension-packs.json",
    "aics-semgrep-rules.json",
)
_STAGE_FINGERPRINT_VERSION = 1


def _digest_payload(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _git_source_revision(target: Path, commit: str) -> str | None:
    if not (target / ".git").exists():
        return None
    result = subprocess.run(  # noqa: S603 - argv-only, no shell
        ["git", "-C", str(target), "rev-parse", commit or "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _source_fingerprint(target: Path, *, commit: str) -> str:
    revision = _git_source_revision(target, commit)
    if revision is not None and (commit or not git_worktree_is_dirty(target)):
        return _digest_payload({"kind": "git", "revision": revision})
    if not target.is_dir():
        return _digest_payload({"kind": "missing", "target": str(target.resolve())})
    entries = build_manifest(target)
    files = [(entry.path, entry.sha256, entry.size) for entry in entries]
    return _digest_payload({"files": files, "git_revision": revision, "kind": "live-manifest"})


def _update_file_digest(digest: Any, path: Path, *, label: str) -> None:
    digest.update(label.encode("utf-8"))
    digest.update(b"\0")
    if path.is_file() and not path.is_symlink():
        digest.update(path.read_bytes())
    else:
        digest.update(b"missing")
    digest.update(b"\0")


def _external_pack_paths(repo_dir: Path) -> list[tuple[str, Path]]:
    registry = repo_dir / "aics-enabled-packs.json"
    try:
        payload = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    paths: list[tuple[str, Path]] = []
    for raw in sorted(str(item) for item in payload):
        path = Path(raw)
        paths.append((raw, path if path.is_absolute() else repo_dir / path))
    return paths


def _hash_active_scanner_inputs(digest: Any, repo_dir: Path) -> None:
    for label, path in _external_pack_paths(repo_dir):
        _update_file_digest(digest, path, label=f"enabled-pack:{label}")
    for root in configured_rules_roots(repo_dir):
        rules_dir = root.resolve() / "rules"
        if not rules_dir.is_dir():
            _update_file_digest(digest, rules_dir, label=f"semgrep-rules:{rules_dir}")
            continue
        for path in sorted(rules_dir.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.suffix in {".yaml", ".yml"}:
                _update_file_digest(
                    digest,
                    path,
                    label=f"semgrep-rule:{rules_dir}:{path.relative_to(rules_dir)}",
                )


def _hash_scanner_package_assets(digest: Any, package_root: Path) -> None:
    """Hash shipped scanner code and runtime assets, excluding local byproducts."""
    for path in sorted(package_root.rglob("*")):
        relative = path.relative_to(package_root)
        if any(part in _SCANNER_EXCLUDED_DIRS for part in relative.parts):
            continue
        if not path.is_file() or path.is_symlink() or path.suffix not in _SCANNER_FILE_SUFFIXES:
            continue
        _update_file_digest(digest, path, label=f"package:{relative.as_posix()}")


def _scanner_configuration_fingerprint(repo_dir: Path) -> str:
    digest = hashlib.sha256()
    _hash_scanner_package_assets(digest, _SCANNER_PACKAGE_ROOT)
    for filename in _REPO_SCANNER_CONFIG_FILES:
        path = repo_dir / filename
        _update_file_digest(digest, path, label=filename)
    _hash_active_scanner_inputs(digest, repo_dir)
    return digest.hexdigest()


def _stage_configuration(stage: str, opts: DriveOptions) -> dict[str, object]:
    stage_index = PIPELINE_STAGES.index(stage)
    config: dict[str, object] = {
        "commit": opts.commit,
        "engine": opts.engine,
        "target_bug_class": opts.target_bug_class,
    }
    if stage_index >= PIPELINE_STAGES.index("nominate") or opts.engine == "llm-heavy":
        config.update(
            {
                "llm_model": opts.llm_model,
                "llm_provider": opts.llm_provider,
                "temperature": opts.temperature,
            }
        )
    if stage_index >= PIPELINE_STAGES.index("gate-1"):
        config["yes"] = opts.yes
    if stage_index >= PIPELINE_STAGES.index("validate"):
        config["no_sandbox"] = opts.no_sandbox
    if stage_index >= PIPELINE_STAGES.index("report"):
        config["bugbounty"] = opts.bugbounty
    return config


def _stage_fingerprint(
    stage: str,
    opts: DriveOptions,
    *,
    source_fingerprint: str,
    scanner_fingerprint: str,
) -> str:
    return _digest_payload(
        {
            "configuration": _stage_configuration(stage, opts),
            "scanner": scanner_fingerprint,
            "source": source_fingerprint,
            "stage": stage,
            "version": _STAGE_FINGERPRINT_VERSION,
        }
    )


# ---------------------------------------------------------------------------
# Interactive prompts
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Prompt:
    """A single decision point.

    ``options`` map single-letter keys to outcomes; ``default`` is what
    the user gets if they press Enter. ``flag_hint`` advertises the CLI
    argument that would skip the prompt on future runs.
    """

    question: str
    flag_hint: str
    options: dict[str, str]
    default: str


def _bell() -> None:
    try:
        sys.stderr.write("\a")
        sys.stderr.flush()
    except OSError:
        pass


def ask(
    prompt: Prompt,
    *,
    input_fn: Callable[[str], str] = input,
    bell_fn: Callable[[], None] = _bell,
) -> str:
    """Render ``prompt`` and return the user's selection (or default)."""
    bell_fn()
    sys.stderr.write(f"\n{prompt.question}\n")
    for key, value in prompt.options.items():
        marker = " (default)" if key == prompt.default else ""
        sys.stderr.write(f"  [{key}] {value}{marker}\n")
    sys.stderr.write(f"  hint: pass {prompt.flag_hint} to skip this next time.\n")
    sys.stderr.write(f"choose [{'/'.join(prompt.options)}] (default {prompt.default}): ")
    sys.stderr.flush()
    raw = input_fn("").strip().lower()
    return raw if raw in prompt.options else prompt.default


# ---------------------------------------------------------------------------
# Stage selection
# ---------------------------------------------------------------------------


def select_phases(
    *,
    phases: str = "",
    start_at: str = "",
    stop_at: str = "",
) -> list[str]:
    """Resolve ``--phases`` / ``--from`` / ``--to`` into an ordered list.

    ``phases`` overrides the others when supplied. Otherwise we slice
    :data:`PIPELINE_STAGES` between ``start_at`` (inclusive) and
    ``stop_at`` (inclusive).
    """
    if phases:
        wanted = [p.strip() for p in phases.split(",") if p.strip()]
        unknown = [p for p in wanted if p not in PIPELINE_STAGES]
        if unknown:
            raise ValueError(f"unknown phase(s): {', '.join(unknown)}")
        return wanted
    start_idx = PIPELINE_STAGES.index(start_at) if start_at else 0
    stop_idx = PIPELINE_STAGES.index(stop_at) + 1 if stop_at else len(PIPELINE_STAGES)
    if start_idx > stop_idx:
        raise ValueError(f"--from {start_at!r} comes after --to {stop_at!r}")
    return list(PIPELINE_STAGES[start_idx:stop_idx])


# ---------------------------------------------------------------------------
# Artefact accounting (zero-result detection)
# ---------------------------------------------------------------------------


def _latest_run_dir(repo_dir: Path) -> Path | None:
    runs_root = repo_dir / "runs"
    if not runs_root.is_dir():
        return None
    candidates = [p for p in runs_root.iterdir() if p.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


_HEX_DIGEST_RE = re.compile(r"[a-f0-9]{64}")
_SAFE_ITEM_ID_RE = re.compile(r"[A-Za-z0-9_.:-]+")
_NOMINATION_HEADERS = (
    "# Nominations",
    "## Stream A —",
    "## Stream B —",
    "## Stream C —",
)
_VALIDATION_LOG_HEADER = (
    "# Validation log\n\n"
    "| finding | status | exit | signal | timed_out | evidence |\n"
    "|---|---|---|---|---|---|\n"
)
_VALIDATION_ROW_RE = re.compile(r"^\| (?P<id>F-[A-Za-z0-9_-]+) \| .+ \|$")
_REPORT_RECEIPT = ".orchestrator-report-artifacts.json"


def _nominate_run_id(fingerprint: str) -> str:
    return f"orchestrator-{fingerprint}"


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _read_text(path: Path) -> str | None:
    if not _regular_file(path):
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def _read_json_object(path: Path) -> dict[str, Any] | None:
    text = _read_text(path)
    if text is None:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _digest_marker_matches(path: Path) -> bool:
    text = _read_text(path)
    return text is not None and _HEX_DIGEST_RE.fullmatch(text.strip()) is not None


def _active_run_dir(repo_dir: Path, state: OrchestratorState) -> Path | None:
    nominate_fingerprint = state.stage_fingerprints.get("nominate")
    if nominate_fingerprint:
        return repo_dir / "runs" / _nominate_run_id(nominate_fingerprint)
    return _latest_run_dir(repo_dir)


def _run_metadata_matches(run_dir: Path, run_id: str, opts: DriveOptions) -> bool:
    data = _read_json_object(run_dir / "run.json")
    if data is None:
        return False
    return (
        data.get("run_id") == run_id
        and str(data.get("llm_provider", "")) == opts.llm_provider
        and str(data.get("llm_model") or "") == opts.llm_model
        and str(data.get("phase", "")) in {"nominate", "analyze", "validate"}
    )


def _nomination_queue_ids(run_dir: Path) -> list[str] | None:
    text = _read_text(run_dir / "queue.jsonl")
    if text is None:
        return None
    candidate_ids: list[str] = []
    try:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    except json.JSONDecodeError:
        return None
    for record in records:
        candidate_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(candidate_id, str) or not _SAFE_ITEM_ID_RE.fullmatch(candidate_id):
            return None
        if candidate_id in candidate_ids:
            return None
        candidate_ids.append(candidate_id)
    return candidate_ids


def _nominations_match_queue(run_dir: Path, candidate_ids: list[str]) -> bool:
    text = _read_text(run_dir / "nominations.md")
    if text is None or any(header not in text for header in _NOMINATION_HEADERS):
        return False
    nominations = parse_nominations(text)
    nomination_ids = [item.nomination_id for item in nominations]
    return len(nominations) == len(candidate_ids) and len(set(nomination_ids)) == len(nominations)


def _nomination_artifacts_are_durable(
    opts: DriveOptions,
    run_dir: Path,
    *,
    run_id: str,
) -> bool:
    if not run_dir.is_dir() or run_dir.is_symlink():
        return False
    if not _run_metadata_matches(run_dir, run_id, opts):
        return False
    candidate_ids = _nomination_queue_ids(run_dir)
    if candidate_ids is None or not _nominations_match_queue(run_dir, candidate_ids):
        return False
    context = _read_text(run_dir / ".nominate-context")
    done_dir = run_dir / ".done"
    if context is None or _HEX_DIGEST_RE.fullmatch(context.strip()) is None:
        return False
    if not done_dir.is_dir() or done_dir.is_symlink():
        return False
    return all(_regular_file(done_dir / candidate_id) for candidate_id in candidate_ids)


def _analysis_item_is_durable(run_dir: Path, nomination_id: str) -> bool:
    finding_id = f"F-{nomination_id.removeprefix('N-')}"
    finding_path = run_dir / "findings" / f"{finding_id}.md"
    text = _read_text(finding_path)
    if text is None or not _digest_marker_matches(run_dir / ".done-analyze" / nomination_id):
        return False
    try:
        finding = parse_finding(text)
    except (TypeError, ValueError):
        return False
    return (
        finding.finding_id == finding_id
        and finding.nomination_id == nomination_id
        and bool(finding.title.strip())
        and bool(finding.body.strip())
    )


def _analysis_artifacts_are_durable(run_dir: Path) -> bool:
    queue_text = _read_text(run_dir / "findings_queue.md")
    findings_dir = run_dir / "findings"
    done_dir = run_dir / ".done-analyze"
    if queue_text is None or not findings_dir.is_dir() or findings_dir.is_symlink():
        return False
    if not done_dir.is_dir() or done_dir.is_symlink():
        return False
    items = parse_queue(queue_text)
    if render_queue(items) != queue_text:
        return False
    return all(_analysis_item_is_durable(run_dir, item.nomination_id) for item in items)


def _findings_by_id(run_dir: Path) -> dict[str, Any] | None:
    findings_dir = run_dir / "findings"
    if not findings_dir.is_dir() or findings_dir.is_symlink():
        return None
    findings: dict[str, Any] = {}
    for path in findings_dir.glob("F-*.md"):
        text = _read_text(path)
        if text is None:
            return None
        try:
            finding = parse_finding(text)
        except (TypeError, ValueError):
            return None
        if not finding.finding_id or finding.finding_id != path.stem:
            return None
        if finding.finding_id in findings:
            return None
        findings[finding.finding_id] = finding
    return findings


def _validation_log_ids(run_dir: Path) -> set[str] | None:
    text = _read_text(run_dir / "validation_log.md")
    if text is None or not text.startswith(_VALIDATION_LOG_HEADER):
        return None
    finding_ids: set[str] = set()
    for line in text.removeprefix(_VALIDATION_LOG_HEADER).splitlines():
        if not line:
            continue
        match = _VALIDATION_ROW_RE.fullmatch(line)
        if match is None or match.group("id") in finding_ids:
            return None
        finding_ids.add(match.group("id"))
    return finding_ids


def _validation_item_is_durable(run_dir: Path, finding_id: str) -> bool:
    if not _digest_marker_matches(run_dir / ".done-validate" / finding_id):
        return False
    poc_dir = run_dir / "sandbox" / finding_id
    if not poc_dir.is_dir() or poc_dir.is_symlink():
        return False
    return any(_regular_file(path) and path.stat().st_size > 0 for path in poc_dir.glob("poc.*"))


def _validation_artifacts_are_durable(run_dir: Path) -> bool:
    findings = _findings_by_id(run_dir)
    logged_ids = _validation_log_ids(run_dir)
    if findings is None or logged_ids is None or not logged_ids <= findings.keys():
        return False
    required_ids = {
        finding_id for finding_id, finding in findings.items() if finding.status != "rejected"
    }
    if not required_ids <= logged_ids:
        return False
    return all(_validation_item_is_durable(run_dir, finding_id) for finding_id in logged_ids)


def _file_digest(path: Path) -> str | None:
    if not _regular_file(path):
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _verified_finding_ids(run_dir: Path) -> set[str] | None:
    findings = _findings_by_id(run_dir)
    if findings is None:
        return None
    return {finding_id for finding_id, finding in findings.items() if finding.status == "verified"}


def _report_files_for_ids(report_root: Path, finding_ids: set[str]) -> dict[str, Path] | None:
    if not finding_ids:
        return {}
    if not report_root.is_dir() or report_root.is_symlink():
        return None
    reports = [path for path in report_root.glob("*.md") if _regular_file(path)]
    selected: dict[str, Path] = {}
    for finding_id in finding_ids:
        marker = f"- finding_id: `{finding_id}`"
        matches = [path for path in reports if marker in (_read_text(path) or "")]
        if not matches:
            return None
        selected[finding_id] = max(matches, key=lambda path: path.stat().st_mtime_ns)
    if len(set(selected.values())) != len(selected):
        return None
    return selected


def _record_report_completion(
    repo_dir: Path,
    run_dir: Path,
    *,
    fingerprint: str,
) -> None:
    receipt_path = repo_dir / _REPORT_RECEIPT
    finding_ids = _verified_finding_ids(run_dir)
    report_root = Path.cwd() / "report"
    files = None if finding_ids is None else _report_files_for_ids(report_root, finding_ids)
    if finding_ids is None or files is None:
        receipt_path.unlink(missing_ok=True)
        return
    artifacts = {
        finding_id: {"name": path.name, "sha256": _file_digest(path)}
        for finding_id, path in files.items()
    }
    payload = {
        "fingerprint": fingerprint,
        "report_root": str(report_root.resolve()),
        "artifacts": artifacts,
    }
    temporary = receipt_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(receipt_path)


def _report_entry_matches(report_root: Path, finding_id: str, value: object) -> bool:
    if not isinstance(value, dict):
        return False
    entry = cast("dict[str, Any]", value)
    name = entry.get("name")
    digest = entry.get("sha256")
    if not isinstance(name, str) or Path(name).name != name:
        return False
    path = report_root / name
    text = _read_text(path)
    return (
        isinstance(digest, str)
        and _file_digest(path) == digest
        and text is not None
        and f"- finding_id: `{finding_id}`" in text
    )


def _report_artifacts_are_durable(
    repo_dir: Path,
    run_dir: Path,
    *,
    fingerprint: str,
) -> bool:
    receipt = _read_json_object(repo_dir / _REPORT_RECEIPT)
    finding_ids = _verified_finding_ids(run_dir)
    report_root = Path.cwd() / "report"
    if receipt is None or finding_ids is None:
        return False
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != finding_ids:
        return False
    if receipt.get("fingerprint") != fingerprint:
        return False
    if receipt.get("report_root") != str(report_root.resolve()):
        return False
    entries_match = all(
        _report_entry_matches(report_root, finding_id, artifacts[finding_id])
        for finding_id in finding_ids
    )
    if not entries_match:
        return False
    artifact_names = {
        cast("dict[str, Any]", artifact).get("name") for artifact in artifacts.values()
    }
    return len(artifact_names) == len(artifacts)


def _clear_marker_dir(path: Path) -> None:
    if not path.is_dir():
        return
    for marker in path.iterdir():
        if marker.is_file() or marker.is_symlink():
            marker.unlink(missing_ok=True)


def _invalidate_inner_stage_cache(repo_dir: Path, stage: str) -> None:
    """Remove generated completion markers when a stage identity changes."""
    if stage == "report":
        (repo_dir / _REPORT_RECEIPT).unlink(missing_ok=True)
    run_dir = _latest_run_dir(repo_dir)
    if run_dir is None:
        return
    marker_names = {
        "nominate": (".done",),
        "analyze": (".done-analyze",),
        "validate": (".done-validate",),
    }.get(stage, ())
    for marker_name in marker_names:
        _clear_marker_dir(run_dir / marker_name)
    if stage == "analyze":
        _clear_marker_dir(repo_dir / ".done-miss-review")
    if stage == "nominate":
        (run_dir / ".nominate-context").unlink(missing_ok=True)
        (run_dir / "nominations.md").unlink(missing_ok=True)


def _prep_cache_is_reusable(repo_dir: Path) -> bool:
    """Accept only an exact durable prep or completed scan generation."""
    return scan_db_stage(repo_dir / "index.duckdb") in {"prep", "complete"}


def _stage_completion_is_reusable(
    stage: str,
    opts: DriveOptions,
    repo_dir: Path,
    *,
    state: OrchestratorState,
    fingerprint: str,
) -> bool:
    """Return whether this stage may satisfy a later pipeline invocation."""
    llm_stages = {"nominate", "analyze", "validate"}
    if stage in llm_stages and not opts.llm_model:
        return False
    if stage == "prep":
        pinned_llm = opts.engine != "llm-heavy" or bool(opts.llm_model)
        return pinned_llm and _prep_cache_is_reusable(repo_dir)
    if stage == "nominate":
        run_id = _nominate_run_id(fingerprint)
        return _nomination_artifacts_are_durable(
            opts,
            repo_dir / "runs" / run_id,
            run_id=run_id,
        )
    if stage not in {"analyze", "validate", "report"}:
        return True
    run_dir = _active_run_dir(repo_dir, state)
    if run_dir is None:
        return False
    if stage == "analyze":
        reusable = _analysis_artifacts_are_durable(run_dir)
    elif stage == "validate":
        reusable = _validation_artifacts_are_durable(run_dir)
    else:
        reusable = _report_artifacts_are_durable(
            repo_dir,
            run_dir,
            fingerprint=fingerprint,
        )
    return reusable


def _invalidate_downstream_state(
    state: OrchestratorState,
    *,
    stage: str,
    repo_dir: Path,
) -> None:
    """Invalidate every stage that may have consumed the rerun stage's output."""
    stage_index = PIPELINE_STAGES.index(stage)
    for downstream in PIPELINE_STAGES[stage_index + 1 :]:
        if downstream in state.completed:
            state.completed.remove(downstream)
        state.stage_fingerprints.pop(downstream, None)
        _invalidate_inner_stage_cache(repo_dir, downstream)


_NEVER_BLOCKS_ON_ZERO: frozenset[str] = frozenset({"prep", "gate-1", "gate-2", "gate-3"})


def _count_nominations(run_dir: Path) -> int:
    nominations = run_dir / "nominations.md"
    if not nominations.is_file():
        return 0
    return sum(
        1 for line in nominations.read_text(encoding="utf-8").splitlines() if line.startswith("- ")
    )


def _count_findings(run_dir: Path) -> int:
    findings = run_dir / "findings"
    return sum(1 for _ in findings.glob("*.md")) if findings.is_dir() else 0


def _count_verified(run_dir: Path) -> int:
    findings = run_dir / "findings"
    if not findings.is_dir():
        return 0
    return sum(
        1
        for fp in findings.glob("*.md")
        if "status: verified" in fp.read_text(encoding="utf-8").lower()
    )


def _count_reports() -> int:
    report_dir = Path.cwd() / "report"
    return sum(1 for _ in report_dir.glob("*.md")) if report_dir.is_dir() else 0


def count_artifacts(repo_dir: Path, stage: str) -> int:  # noqa: PLR0911 - flat dispatch
    """Return how many actionable artefacts ``stage`` produced.

    ``-1`` means the stage never participates in the zero-output prompt
    (HITL gates and ``prep`` are always considered productive).
    """
    if stage in _NEVER_BLOCKS_ON_ZERO:
        return -1
    if stage == "report":
        return _count_reports()
    last = _latest_run_dir(repo_dir)
    if last is None:
        return 0
    if stage == "nominate":
        return _count_nominations(last)
    if stage == "analyze":
        return _count_findings(last)
    if stage == "validate":
        return _count_verified(last)
    return -1


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class StageOutcome:
    rc: int
    stderr: str


def _run_subprocess(argv: list[str]) -> StageOutcome:
    """Streaming subprocess runner. Mirrors stdout live; captures stderr."""
    proc = subprocess.Popen(  # noqa: S603 - argv-only, no shell
        argv,
        stdout=None,  # inherit so users see live progress
        stderr=subprocess.PIPE,
        text=True,
    )
    stderr_chunks: list[str] = []
    assert proc.stderr is not None
    for line in proc.stderr:
        sys.stderr.write(line)
        stderr_chunks.append(line)
    rc = proc.wait()
    return StageOutcome(rc=rc, stderr="".join(stderr_chunks))


@dataclass(slots=True)
class DriveOptions:
    cache_root: Path
    target: Path
    repo_id: str
    phases: list[str]
    llm_provider: str
    llm_model: str
    temperature: float
    target_bug_class: str
    commit: str
    yes: bool
    no_sandbox: bool
    bugbounty: bool
    engine: str = "hybrid"


def _base_argv(opts: DriveOptions, stage: str) -> list[str]:
    return ["ai-codescan", "--cache-dir", str(opts.cache_root), stage]


def _prep_argv(opts: DriveOptions, _: str) -> list[str]:
    argv = [
        *_base_argv(opts, "prep"),
        str(opts.target),
        "--llm-provider",
        opts.llm_provider,
    ]
    if opts.llm_model:
        argv += ["--llm-model", opts.llm_model]
    argv += ["--engine", opts.engine]
    if opts.commit:
        argv += ["--commit", opts.commit]
    if opts.target_bug_class:
        argv += ["--target-bug-class", opts.target_bug_class]
    return argv


def _nominate_argv(opts: DriveOptions, fingerprint: str) -> list[str]:
    argv = [
        *_base_argv(opts, "nominate"),
        "--repo-id",
        opts.repo_id,
        "--temperature",
        str(opts.temperature),
        "--llm-provider",
        opts.llm_provider,
    ]
    if opts.llm_model:
        argv += ["--llm-model", opts.llm_model]
    if fingerprint:
        argv += ["--run-id", _nominate_run_id(fingerprint)]
    if opts.target_bug_class:
        argv += ["--target-bug-class", opts.target_bug_class]
    return argv


def _gate_argv(opts: DriveOptions, stage: str) -> list[str]:
    argv = [*_base_argv(opts, stage), "--repo-id", opts.repo_id]
    if opts.yes:
        argv.append("--yes")
    return argv


def _analyze_argv(opts: DriveOptions, _: str) -> list[str]:
    argv = [
        *_base_argv(opts, "analyze"),
        "--repo-id",
        opts.repo_id,
        "--temperature",
        str(opts.temperature),
        "--llm-provider",
        opts.llm_provider,
    ]
    if opts.llm_model:
        argv += ["--llm-model", opts.llm_model]
    return argv


def _validate_argv(opts: DriveOptions, _: str) -> list[str]:
    argv = [
        *_base_argv(opts, "validate"),
        "--repo-id",
        opts.repo_id,
        "--llm-provider",
        opts.llm_provider,
    ]
    if opts.llm_model:
        argv += ["--llm-model", opts.llm_model]
    if opts.no_sandbox:
        argv.append("--no-sandbox")
    return argv


def _report_argv(opts: DriveOptions, _: str) -> list[str]:
    argv = [*_base_argv(opts, "report"), "--repo-id", opts.repo_id]
    if opts.bugbounty:
        argv.append("--bugbounty")
    return argv


_STAGE_ARGV_BUILDERS: dict[str, Callable[[DriveOptions, str], list[str]]] = {
    "prep": _prep_argv,
    "nominate": _nominate_argv,
    "gate-1": _gate_argv,
    "gate-2": _gate_argv,
    "gate-3": _gate_argv,
    "analyze": _analyze_argv,
    "validate": _validate_argv,
    "report": _report_argv,
}


_ABORT = "abort"
_CONTINUE = "continue"


def _build_argv(
    stage: str,
    opts: DriveOptions,
    *,
    stage_fingerprint: str = "",
) -> list[str]:
    builder = _STAGE_ARGV_BUILDERS.get(stage)
    if builder is None:
        raise ValueError(f"unknown stage: {stage}")
    return builder(opts, stage_fingerprint if stage == "nominate" else stage)


def _handle_failure(  # noqa: PLR0913 - keyword-only fan-in
    *,
    stage: str,
    argv: list[str],
    outcome: StageOutcome,
    opts: DriveOptions,
    state: OrchestratorState,
    runner: Callable[[list[str]], StageOutcome],
    asker: Callable[[Prompt], str],
) -> tuple[StageOutcome, str]:
    """Apply rate-limit / auth recovery flow.

    Returns ``(outcome, action)`` where ``action`` is ``"continue"`` (move
    on, possibly with a fresh outcome), ``"skip"`` (mark complete, move
    to next stage), or ``"abort"`` (return the failing rc).
    """
    if opts.yes or not detect_rate_limit_or_auth(outcome.stderr):
        return outcome, _ABORT
    choice = asker(
        Prompt(
            question=(
                f"stage {stage!r} failed; stderr looks like an LLM rate-limit or auth problem"
            ),
            flag_hint="--yes (always continue) or fix credentials and rerun",
            options={"r": "retry now", "s": "skip this stage", "a": "abort"},
            default="r",
        )
    )
    state.decisions[f"{stage}:rate_limit"] = choice
    save_state(opts.cache_root, state)
    if choice == "r":
        return runner(argv), _CONTINUE
    if choice == "s":
        return outcome, "skip"
    return outcome, _ABORT


def _handle_zero_output(  # noqa: PLR0913 - keyword-only fan-in
    *,
    stage: str,
    argv: list[str],
    opts: DriveOptions,
    state: OrchestratorState,
    runner: Callable[[list[str]], StageOutcome],
    asker: Callable[[Prompt], str],
) -> tuple[StageOutcome | None, str]:
    """Prompt on empty stage output.

    Returns ``(outcome_or_none, action)``: ``"continue"`` when we move on
    (either accepting the empty result or after a successful retry),
    ``"abort"`` when the user wants to stop, or ``"fail"`` when a retry
    itself failed.
    """
    choice = asker(
        Prompt(
            question=f"stage {stage!r} produced zero actionable artefacts",
            flag_hint="--yes (continue silently on empty output)",
            options={
                "c": "continue with next stage anyway",
                "r": "retry this stage",
                "a": "abort",
            },
            default="c",
        )
    )
    state.decisions[f"{stage}:zero_output"] = choice
    save_state(opts.cache_root, state)
    if choice == "r":
        outcome = runner(argv)
        return (outcome, "fail" if outcome.rc != 0 else _CONTINUE)
    if choice == "a":
        return None, _ABORT
    return None, _CONTINUE


def _prepare_stage_attempt(
    state: OrchestratorState,
    opts: DriveOptions,
    *,
    stage: str,
    repo_dir: Path,
    fingerprints: tuple[str, str],
) -> str | None:
    """Return the stage fingerprint, or None when a reusable completion exists."""
    source_fingerprint, scanner_fingerprint = fingerprints
    fingerprint = _stage_fingerprint(
        stage,
        opts,
        source_fingerprint=source_fingerprint,
        scanner_fingerprint=scanner_fingerprint,
    )
    previous_fingerprint = state.stage_fingerprints.get(stage)
    reusable = _stage_completion_is_reusable(
        stage,
        opts,
        repo_dir,
        state=state,
        fingerprint=fingerprint,
    )
    if stage in state.completed and previous_fingerprint == fingerprint and reusable:
        sys.stderr.write(f"[orchestrator] skipping {stage} (already complete)\n")
        return None
    inputs_changed = previous_fingerprint is not None and previous_fingerprint != fingerprint
    resuming_attempt = (
        previous_fingerprint == fingerprint
        and stage not in state.completed
        and bool(state.last_error and state.last_error.startswith(f"{stage}:"))
    )
    if (stage in state.completed or inputs_changed or not reusable) and not resuming_attempt:
        _invalidate_inner_stage_cache(repo_dir, stage)
    _invalidate_downstream_state(state, stage=stage, repo_dir=repo_dir)
    if stage in state.completed:
        state.completed.remove(stage)
        sys.stderr.write(f"[orchestrator] rerunning {stage} (inputs changed)\n")
    elif inputs_changed:
        sys.stderr.write(f"[orchestrator] restarting {stage} (attempt inputs changed)\n")
    state.stage_fingerprints[stage] = fingerprint
    state.last_error = f"{stage}: in-progress"
    save_state(opts.cache_root, state)
    return fingerprint


def _mark_stage_complete(
    state: OrchestratorState,
    opts: DriveOptions,
    *,
    stage: str,
    repo_dir: Path,
    fingerprint: str,
) -> None:
    run_dir = _active_run_dir(repo_dir, state)
    if stage == "report" and run_dir is not None:
        _record_report_completion(repo_dir, run_dir, fingerprint=fingerprint)
    reusable = _stage_completion_is_reusable(
        stage,
        opts,
        repo_dir,
        state=state,
        fingerprint=fingerprint,
    )
    if reusable:
        state.completed.append(stage)
    else:
        sys.stderr.write(f"[orchestrator] {stage} completed for this run but is not reusable\n")
    state.stage_fingerprints[stage] = fingerprint
    state.last_error = None
    save_state(opts.cache_root, state)


def drive_pipeline(  # noqa: PLR0912 - top-level loop; helpers absorb the rest
    opts: DriveOptions,
    *,
    runner: Callable[[list[str]], StageOutcome] = _run_subprocess,
    asker: Callable[[Prompt], str] = ask,
) -> int:
    """Execute the configured phases in order.

    Returns the exit code of the last failing stage (or 0 on full
    success). Persists progress to ``run.state.json`` after every stage.
    """
    state = load_state(opts.cache_root, opts.repo_id) or OrchestratorState(
        repo_id=opts.repo_id,
        target=str(opts.target),
        phases=list(opts.phases),
    )
    state.phases = list(opts.phases)
    save_state(opts.cache_root, state)

    repo_dir = opts.cache_root / opts.repo_id
    source_fingerprint = _source_fingerprint(opts.target, commit=opts.commit)
    scanner_fingerprint = _scanner_configuration_fingerprint(repo_dir)

    for stage in opts.phases:
        fingerprint = _prepare_stage_attempt(
            state,
            opts,
            stage=stage,
            repo_dir=repo_dir,
            fingerprints=(source_fingerprint, scanner_fingerprint),
        )
        if fingerprint is None:
            continue
        sys.stderr.write(f"\n[orchestrator] === {stage} ===\n")
        argv = _build_argv(stage, opts, stage_fingerprint=fingerprint)
        outcome = runner(argv)

        if outcome.rc != 0:
            outcome, action = _handle_failure(
                stage=stage,
                argv=argv,
                outcome=outcome,
                opts=opts,
                state=state,
                runner=runner,
                asker=asker,
            )
            if action == "skip":
                reusable = _stage_completion_is_reusable(
                    stage,
                    opts,
                    repo_dir,
                    state=state,
                    fingerprint=fingerprint,
                )
                if reusable:
                    state.completed.append(stage)
                state.stage_fingerprints[stage] = fingerprint
                state.last_error = f"{stage}: user-skipped after auth/rate-limit"
                save_state(opts.cache_root, state)
                continue
            if action == _ABORT or outcome.rc != 0:
                state.last_error = f"{stage}: rc={outcome.rc}"
                save_state(opts.cache_root, state)
                return outcome.rc

        if not opts.yes and count_artifacts(repo_dir, stage) == 0:
            retry, action = _handle_zero_output(
                stage=stage,
                argv=argv,
                opts=opts,
                state=state,
                runner=runner,
                asker=asker,
            )
            if action == "fail":
                assert retry is not None
                state.last_error = f"{stage}: rc={retry.rc} (retry)"
                save_state(opts.cache_root, state)
                return retry.rc
            if action == _ABORT:
                state.last_error = f"{stage}: aborted on zero output"
                save_state(opts.cache_root, state)
                return 0

        _mark_stage_complete(
            state,
            opts,
            stage=stage,
            repo_dir=repo_dir,
            fingerprint=fingerprint,
        )

    return 0


def preflight_llm_choice(
    *,
    provider_supplied: bool,
    model_supplied: bool,
    yes: bool,
    asker: Callable[[Prompt], str] = ask,
) -> tuple[str | None, str | None]:
    """Confirm LLM provider/model when the user didn't pin them on the CLI.

    Returns ``(provider, model)`` or ``(None, None)`` when ``--yes`` /
    user accepts the defaults. The caller substitutes the existing
    defaults for any ``None`` value.
    """
    if yes:
        return (None, None)
    provider: str | None = None
    model: str | None = None
    if not provider_supplied:
        choice = asker(
            Prompt(
                question="No --llm-provider given; which CLI should drive the LLM stages?",
                flag_hint="--llm-provider claude|gemini|codex",
                options={"c": "claude (default)", "g": "gemini", "x": "codex"},
                default="c",
            )
        )
        provider = {"c": "claude", "g": "gemini", "x": "codex"}[choice]
    if not model_supplied:
        choice = asker(
            Prompt(
                question="No --llm-model given; pin a specific model or use the CLI default?",
                flag_hint="--llm-model <name>",
                options={"d": "default (whatever the CLI picks)", "p": "type a model name"},
                default="d",
            )
        )
        if choice == "p":
            sys.stderr.write("model name: ")
            sys.stderr.flush()
            model = input("").strip() or None
    return (provider, model)


__all__ = [
    "DriveOptions",
    "OrchestratorState",
    "PIPELINE_STAGES",
    "Prompt",
    "StageOutcome",
    "ask",
    "count_artifacts",
    "detect_rate_limit_or_auth",
    "drive_pipeline",
    "load_state",
    "preflight_llm_choice",
    "save_state",
    "select_phases",
    "state_path",
]


# Silence the unused-import warning for the sole non-stdlib import used in
# type-only context (Iterable kept here so future extension is obvious).
_ = Iterable
