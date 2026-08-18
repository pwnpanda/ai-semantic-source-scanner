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
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ai_codescan.manifest import build_manifest

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


_SCANNER_FILE_SUFFIXES = frozenset({".json", ".md", ".py", ".pyi", ".sc", ".sh", ".yaml", ".yml"})
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
    if commit and revision is not None:
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


def _active_semgrep_roots(repo_dir: Path) -> list[Path]:
    roots = [repo_dir / ".semgrep"]
    registry = repo_dir / "aics-semgrep-rules.json"
    try:
        payload = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return roots
    if isinstance(payload, dict) and payload.get("rules_root"):
        roots.append(Path(str(payload["rules_root"])).expanduser())
    return roots


def _hash_active_scanner_inputs(digest: Any, repo_dir: Path) -> None:
    for label, path in _external_pack_paths(repo_dir):
        _update_file_digest(digest, path, label=f"enabled-pack:{label}")
    for root in _active_semgrep_roots(repo_dir):
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


def _scanner_configuration_fingerprint(repo_dir: Path) -> str:
    package_root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for path in sorted(package_root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix not in _SCANNER_FILE_SUFFIXES:
            continue
        digest.update(path.relative_to(package_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
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


def _clear_marker_dir(path: Path) -> None:
    if not path.is_dir():
        return
    for marker in path.iterdir():
        if marker.is_file() or marker.is_symlink():
            marker.unlink(missing_ok=True)


def _invalidate_inner_stage_cache(repo_dir: Path, stage: str) -> None:
    """Remove generated completion markers when a stage identity changes."""
    run_dir = _latest_run_dir(repo_dir)
    if run_dir is None:
        return
    marker_names = {
        "analyze": (".done-analyze",),
        "validate": (".done-validate",),
    }.get(stage, ())
    for marker_name in marker_names:
        _clear_marker_dir(run_dir / marker_name)
    if stage == "analyze":
        _clear_marker_dir(repo_dir / ".done-miss-review")


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


# ``ai-codescan ...`` argv builders for each stage. Kept tiny so the
# orchestrator stays declarative and the per-stage flag plumbing lives in
# one obvious place.
def _argv_for(  # noqa: PLR0911, PLR0912, PLR0913 - direct mapping; flattening hurts readability
    stage: str,
    *,
    cache_root: Path,
    target: Path,
    repo_id: str,
    llm_provider: str,
    llm_model: str,
    temperature: float,
    target_bug_class: str,
    commit: str,
    yes: bool,
    no_sandbox: bool,
    bugbounty: bool,
    engine: str = "hybrid",
) -> list[str]:
    base = ["ai-codescan", "--cache-dir", str(cache_root)]
    if stage == "prep":
        argv = [*base, "prep", str(target), "--llm-provider", llm_provider]
        if llm_model:
            argv += ["--llm-model", llm_model]
        argv += ["--engine", engine]
        if commit:
            argv += ["--commit", commit]
        if target_bug_class:
            argv += ["--target-bug-class", target_bug_class]
        return argv
    if stage == "nominate":
        argv = [
            *base,
            "nominate",
            "--repo-id",
            repo_id,
            "--temperature",
            str(temperature),
            "--llm-provider",
            llm_provider,
        ]
        if llm_model:
            argv += ["--llm-model", llm_model]
        if target_bug_class:
            argv += ["--target-bug-class", target_bug_class]
        return argv
    if stage in {"gate-1", "gate-2", "gate-3"}:
        argv = [*base, stage, "--repo-id", repo_id]
        if yes:
            argv.append("--yes")
        return argv
    if stage == "analyze":
        argv = [
            *base,
            "analyze",
            "--repo-id",
            repo_id,
            "--temperature",
            str(temperature),
            "--llm-provider",
            llm_provider,
        ]
        if llm_model:
            argv += ["--llm-model", llm_model]
        return argv
    if stage == "validate":
        argv = [
            *base,
            "validate",
            "--repo-id",
            repo_id,
            "--llm-provider",
            llm_provider,
        ]
        if llm_model:
            argv += ["--llm-model", llm_model]
        if no_sandbox:
            argv.append("--no-sandbox")
        return argv
    if stage == "report":
        argv = [*base, "report", "--repo-id", repo_id]
        if bugbounty:
            argv.append("--bugbounty")
        return argv
    raise ValueError(f"unknown stage: {stage}")


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


_ABORT = "abort"
_CONTINUE = "continue"


def _build_argv(stage: str, opts: DriveOptions) -> list[str]:
    return _argv_for(
        stage,
        engine=opts.engine,
        cache_root=opts.cache_root,
        target=opts.target,
        repo_id=opts.repo_id,
        llm_provider=opts.llm_provider,
        llm_model=opts.llm_model,
        temperature=opts.temperature,
        target_bug_class=opts.target_bug_class,
        commit=opts.commit,
        yes=opts.yes,
        no_sandbox=opts.no_sandbox,
        bugbounty=opts.bugbounty,
    )


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
        fingerprint = _stage_fingerprint(
            stage,
            opts,
            source_fingerprint=source_fingerprint,
            scanner_fingerprint=scanner_fingerprint,
        )
        previous_fingerprint = state.stage_fingerprints.get(stage)
        if stage in state.completed and previous_fingerprint == fingerprint:
            sys.stderr.write(f"[orchestrator] skipping {stage} (already complete)\n")
            continue
        if stage in state.completed or (
            previous_fingerprint is not None and previous_fingerprint != fingerprint
        ):
            _invalidate_inner_stage_cache(repo_dir, stage)
        if stage in state.completed:
            state.completed.remove(stage)
            sys.stderr.write(f"[orchestrator] rerunning {stage} (inputs changed)\n")
        elif previous_fingerprint is not None and previous_fingerprint != fingerprint:
            sys.stderr.write(f"[orchestrator] restarting {stage} (attempt inputs changed)\n")
        state.stage_fingerprints[stage] = fingerprint
        save_state(opts.cache_root, state)
        sys.stderr.write(f"\n[orchestrator] === {stage} ===\n")
        argv = _build_argv(stage, opts)
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

        state.completed.append(stage)
        state.stage_fingerprints[stage] = fingerprint
        state.last_error = None
        save_state(opts.cache_root, state)

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
