"""Command-line entry point for ai-codescan."""

from __future__ import annotations

import contextlib
import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import Annotated, Any
from typing import cast as _cast

import duckdb
import typer
import yaml

from ai_codescan.analyzer import ReviewLimits, run_analyzer
from ai_codescan.artifact_id import project_artifact_id
from ai_codescan.cache_state import (
    build_scan_fingerprint,
    scan_db_stage,
    scan_db_stage_is_current,
)
from ai_codescan.config import compute_repo_id, default_cache_root
from ai_codescan.engines.codeql import run_queries
from ai_codescan.engines.hybrid import run_hybrid
from ai_codescan.engines.llm_heavy import run_llm_heavy_engine
from ai_codescan.engines.semgrep import register_rules_root
from ai_codescan.eval import (
    compare_eval_results,
    load_eval_cases,
    load_eval_results,
    run_ai_codescan_case,
    write_eval_comparison,
    write_eval_outputs,
)
from ai_codescan.evidence import evidence_bundle_from_jsonable
from ai_codescan.findings.model import Finding, parse_finding
from ai_codescan.gate import apply_yes_to_all, selected_extensions
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.ingest.sarif import ingest_sarif
from ai_codescan.llm import LLMConfig, UnknownProviderError, is_available
from ai_codescan.miss_finder import write_miss_candidates
from ai_codescan.model_proposals import (
    accept_model_proposal,
    apply_proposal_to_semgrep,
    link_eval_targets,
    list_model_proposals,
    proposal_decision_counts,
    proposals_from_verdicts,
    record_proposal_decision,
    write_model_proposals,
)
from ai_codescan.nominator import run_nominator, write_llm_cmd_script
from ai_codescan.prep import run_prep
from ai_codescan.repo_lock import RepoScanLockedError, repo_scan_lock
from ai_codescan.report import write_candidate_audit, write_report
from ai_codescan.runs.orchestrator import (
    PIPELINE_STAGES,
    DriveOptions,
    drive_pipeline,
    preflight_llm_choice,
    select_phases,
)
from ai_codescan.runs.state import load_or_create
from ai_codescan.server import serve as start_server
from ai_codescan.snapshot import SnapshotResult, force_remove
from ai_codescan.stack_detect import Project, ProjectKind, detect_projects
from ai_codescan.storage_taint import (
    find_unresolved_dynamic_calls,
    load_schema_yaml,
    merge_proposals_into_schema,
    parse_resolver_proposals,
    run_full_fixpoint,
    save_schema_yaml,
    write_resolver_queue,
)
from ai_codescan.taxonomy.diff import (
    apply_diff,
    days_since_last_check,
    diff_against_installed_codeql,
    mark_taxonomy_checked,
    maybe_run_periodic_check,
)
from ai_codescan.taxonomy.loader import (
    BugClass,
    UnknownBugClassError,
    list_classes,
    resolve_classes,
)
from ai_codescan.validator import run_validator
from ai_codescan.views import render_file_view
from ai_codescan.visualize import OutputFormat
from ai_codescan.visualize import render as render_graph

_BYTES_PER_KIB = 1024

app = typer.Typer(
    name="ai-codescan",
    help="AI-driven SAST pipeline (Phase 1A: prep produces snapshot + repo.md).",
    no_args_is_help=True,
)
cache_app = typer.Typer(name="cache", help="Manage cached repos.", no_args_is_help=True)
app.add_typer(cache_app)
eval_app = typer.Typer(name="eval", help="Run scanner evaluation targets.", no_args_is_help=True)
app.add_typer(eval_app)
model_proposals_app = typer.Typer(
    name="model-proposals",
    help="Manage model-extension proposal artifacts.",
    no_args_is_help=True,
)
app.add_typer(model_proposals_app)


_CacheDirOption = Annotated[
    Path | None,
    typer.Option(
        "--cache-dir",
        help="Override the cache root (default: ~/.ai_codescan/repos).",
    ),
]
_CommitOption = Annotated[
    str | None,
    typer.Option("--commit", help="Pin snapshot to a specific git commit SHA."),
]
_QuietOption = Annotated[bool, typer.Option("--quiet", "-q", help="Suppress non-error output.")]
_VerboseOption = Annotated[bool, typer.Option("--verbose", "-v", help="Verbose logging.")]


def _prep_bug_classes(target_bug_class: str) -> list[BugClass]:
    if not target_bug_class:
        return list_classes()
    try:
        return resolve_classes(
            [token.strip() for token in target_bug_class.split(",") if token.strip()]
        )
    except UnknownBugClassError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


_HYBRID_LANGUAGES = {
    ProjectKind.NODE: "javascript",
    ProjectKind.PYTHON: "python",
    ProjectKind.GO: "go",
    ProjectKind.RUBY: "ruby",
    ProjectKind.PHP: "php",
    ProjectKind.CSHARP: "csharp",
}


def _hybrid_language(snapshot_root: Path, project: Project) -> str | None:
    if project.kind is not ProjectKind.JAVA:
        return _HYBRID_LANGUAGES.get(project.kind)
    project_dir = snapshot_root / project.base_path
    java_count = sum(1 for _ in project_dir.rglob("*.java"))
    kotlin_count = sum(1 for path in project_dir.rglob("*") if path.suffix in {".kt", ".kts"})
    return "kotlin" if kotlin_count > java_count else "java"


def _hybrid_project_roots(snapshot_root: Path) -> list[tuple[Path, str, str]]:
    roots: list[tuple[Path, str, str]] = []
    for project in detect_projects(snapshot_root):
        language = _hybrid_language(snapshot_root, project)
        if language is None:
            continue
        project_id = project_artifact_id(project.name, project.base_path)
        roots.append((snapshot_root / project.base_path, project_id, language))
    return roots


def _run_post_prep_engine(  # noqa: PLR0913 - one positional arg; scan context is keyword-only
    engine: str,
    *,
    snapshot: SnapshotResult,
    repo_dir: Path,
    db_path: Path,
    bug_classes: list[BugClass],
    llm: LLMConfig,
    quiet: bool,
) -> None:
    fingerprint = build_scan_fingerprint(
        repo_dir,
        engine=engine,
        bug_classes=bug_classes,
        engine_config=(
            {"llm_provider": llm.provider, "llm_model": llm.model or ""}
            if engine == "llm-heavy"
            else None
        ),
    )
    full_scan_reused = scan_db_stage_is_current(
        db_path,
        fingerprint=fingerprint,
        engine=engine,
        required_stage="complete",
    )
    if engine == "llm-heavy":
        if full_scan_reused:
            if not quiet:
                typer.echo("llm-heavy: cached complete stage reused")
            return
        state = load_or_create(
            repo_dir,
            engine="llm-heavy",
            temperature=0.0,
            target_bug_classes=[item.name for item in bug_classes],
            llm_provider=llm.provider,
            llm_model=llm.model,
        )
        count = run_llm_heavy_engine(
            state,
            repo_dir=repo_dir,
            db_path=db_path,
            target_bug_classes=[item.name for item in bug_classes],
            llm=llm,
            scan_fingerprint=fingerprint,
        )
        if not quiet:
            typer.echo(f"llm-heavy ingested {count} flow(s)")
        return
    if engine != "hybrid":
        return
    stats = run_hybrid(
        _hybrid_project_roots(snapshot.snapshot_dir),
        snapshot_root=snapshot.snapshot_dir,
        repo_dir=repo_dir,
        db_path=db_path,
        scan_fingerprint=fingerprint,
    )
    if not quiet:
        typer.echo(
            f"hybrid: codeql={stats.codeql_flows} semgrep={stats.semgrep_flows} "
            f"joern={stats.joern_flows} deduped={stats.deduped}"
        )


def _report_prep(
    snapshot: SnapshotResult,
    *,
    db_path: Path,
    bug_classes: list[BugClass],
    engine: str,
) -> None:
    status_word = "skipped" if snapshot.skipped else "took"
    commit_label = f" @ {snapshot.commit_sha[:8]}" if snapshot.commit_sha else ""
    typer.echo(f"snapshot {status_word} ({snapshot.method}){commit_label}")
    typer.echo(f"index at {db_path}")
    typer.echo(f"bug classes: {', '.join(item.name for item in bug_classes)}")
    typer.echo(f"engine: {engine}")
    check = maybe_run_periodic_check()
    if check is not None and check.missing_tags:
        typer.echo(
            f"note: taxonomy may be stale — {len(check.missing_tags)} CodeQL "
            "tag(s) not in bug_classes.yaml. Run `ai-codescan taxonomy diff`."
        )


@app.callback()
def _root(
    ctx: typer.Context,
    cache_dir: _CacheDirOption = None,
    quiet: _QuietOption = False,
    verbose: _VerboseOption = False,
) -> None:
    """Top-level options shared by every subcommand."""
    ctx.obj = {
        "cache_root": cache_dir if cache_dir is not None else default_cache_root(),
        "quiet": quiet,
        "verbose": verbose,
    }


@app.command(epilog="Global options: --cache-dir, --quiet, --verbose (pass before subcommand).")
def prep(  # noqa: PLR0913, PLR0912, PLR0915 - flag plumbing + multi-stage orchestration
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Target repo to scan.")],
    commit: _CommitOption = None,
    engine: Annotated[
        str,
        typer.Option(
            "--engine",
            help="Static prep engine: hybrid (recommended), codeql, or llm-heavy.",
        ),
    ] = "codeql",
    llm_provider: Annotated[
        str,
        typer.Option(
            "--llm-provider",
            help="LLM CLI for --engine llm-heavy: claude, gemini, or codex.",
        ),
    ] = "claude",
    llm_model: Annotated[
        str,
        typer.Option("--llm-model", help="Specific model for --engine llm-heavy."),
    ] = "",
    target_bug_class: Annotated[
        str,
        typer.Option(
            "--target-bug-class",
            help="Comma-separated names or @groups (default: all).",
        ),
    ] = "",
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Bypass the incremental short-circuit and re-run AST/SCIP/CodeQL.",
        ),
    ] = False,
) -> None:
    """Snapshot, detect, AST, SCIP, then run engines and ingest into DuckDB.

    Scan trusted source only: some SCIP and CodeQL indexers execute the
    target project's build tooling outside a sandbox.
    """
    if engine not in {"codeql", "llm-heavy", "hybrid"}:
        typer.echo(
            f"--engine {engine} is not supported. "
            "Use 'codeql' (default), 'llm-heavy', or 'hybrid'.",
            err=True,
        )
        raise typer.Exit(code=2)
    if not target.is_dir():
        typer.echo(f"Target is not a directory: {target}", err=True)
        raise typer.Exit(code=2)

    bug_classes = _prep_bug_classes(target_bug_class)
    llm = _build_llm_config(llm_provider, llm_model)
    cache_root: Path = ctx.obj["cache_root"]
    quiet: bool = ctx.obj["quiet"]
    repo_dir = cache_root / compute_repo_id(target)
    try:
        with repo_scan_lock(repo_dir):
            snap, db_path = run_prep(
                target,
                cache_root=cache_root,
                commit=commit,
                bug_classes=bug_classes,
                engine=engine,
                llm_provider=llm.provider,
                llm_model=llm.model or "",
                quiet=quiet,
                force=force,
            )
            if snap.index_reused and not quiet:
                typer.echo("incremental: skipping AST/SCIP/CodeQL stages — cached results reused")
            _run_post_prep_engine(
                engine=engine,
                snapshot=snap,
                repo_dir=repo_dir,
                db_path=db_path,
                bug_classes=bug_classes,
                llm=llm,
                quiet=quiet,
            )
    except RepoScanLockedError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if (cache_stage := scan_db_stage(db_path)) and cache_stage != "complete":
        typer.echo(
            "warning: scan completed with unpinned or unavailable analyzer inputs; "
            "the prep cache remains retryable",
            err=True,
        )
    if not quiet:
        _report_prep(snap, db_path=db_path, bug_classes=bug_classes, engine=engine)


@app.command("list-bug-classes")
def list_bug_classes() -> None:
    """Print every taxonomy entry."""
    rows = sorted(list_classes(), key=lambda c: c.name)
    for c in rows:
        aliases = f" ({', '.join(c.aliases)})" if c.aliases else ""
        cwes = ", ".join(c.cwes)
        typer.echo(f"{c.name}{aliases}\t{c.group}\t{cwes}")


taxonomy_app = typer.Typer(
    name="taxonomy", help="Maintain bug-class taxonomy.", no_args_is_help=True
)
app.add_typer(taxonomy_app)


@taxonomy_app.command("diff")
def taxonomy_diff(
    apply: Annotated[
        bool,
        typer.Option("--apply", help="Append suggested stubs to bug_classes.yaml."),
    ] = False,
) -> None:
    """Diff our taxonomy against installed CodeQL packs."""
    diff = diff_against_installed_codeql()
    mark_taxonomy_checked()
    if diff.is_empty:
        typer.echo("taxonomy is up to date with installed CodeQL packs")
        return
    typer.echo(f"missing tags: {len(diff.missing_tags)}")
    for tag in diff.missing_tags:
        typer.echo(f"  - {tag}")
    if apply:
        appended = apply_diff(diff)
        typer.echo(f"appended {appended} stub entries to bug_classes.yaml; review and rename")
    else:
        typer.echo("\nSuggested stubs (run with --apply to merge):\n")
        typer.echo(diff.suggested_stubs_yaml)


@taxonomy_app.command("check")
def taxonomy_check() -> None:
    """One-line status: how stale is the taxonomy + how many missing tags."""
    days = days_since_last_check()
    age = f"{days}d ago" if days is not None else "never"
    diff = diff_against_installed_codeql()
    missing = len(diff.missing_tags)
    typer.echo(f"taxonomy: last checked {age}, missing tags: {missing}")


def _format_rows(columns: list[str], rows: list[tuple[Any, ...]]) -> str:
    """Render rows as an aligned text table (replacement for pandas to_string)."""
    if not rows:
        return "(no rows)"
    str_rows = [[str(v) if v is not None else "" for v in row] for row in rows]
    widths = [max(len(columns[i]), *(len(r[i]) for r in str_rows)) for i in range(len(columns))]
    header = "  ".join(col.rjust(widths[i]) for i, col in enumerate(columns))
    body = "\n".join(
        "  ".join(cell.rjust(widths[i]) for i, cell in enumerate(row)) for row in str_rows
    )
    return f"{header}\n{body}"


def _resolve_repo_id(cache_root: Path, repo_id: str) -> str:
    """Pick the cached repo by id, or auto-select if exactly one exists."""
    if repo_id:
        return repo_id
    if not cache_root.exists():
        typer.echo("Cache directory does not exist.", err=True)
        raise typer.Exit(code=1)
    repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
    if len(repos) != 1:
        typer.echo("Specify --repo-id (zero or multiple cached repos exist).", err=True)
        raise typer.Exit(code=1)
    return repos[0]


def _latest_run_dir(repo_dir: Path) -> Path:
    runs_root = repo_dir / "runs"
    if not runs_root.is_dir() or not any(runs_root.iterdir()):
        typer.echo("No runs found.", err=True)
        raise typer.Exit(code=1)
    return max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)


def _rescore_candidates(
    conn: duckdb.DuckDBPyConnection,
    *,
    source_root: Path,
) -> int:
    """Rebuild the candidate queue and re-persist scores.

    Used after `adversarial-review` so a challenger's dispute shifts the
    candidate ranking immediately (Phase 13 `_adversarial_factor`). Returns
    the number of candidates re-scored.
    """
    # Function-scope imports: `nominator` transitively reaches the CLI module
    # surface, so a top-level import would cycle.
    from ai_codescan.nominator import build_queue  # noqa: PLC0415
    from ai_codescan.scoring import (  # noqa: PLC0415
        persist_candidate_scores,
        score_candidates,
    )

    queue = build_queue(conn, target_bug_classes=[])
    scores = score_candidates(conn, queue, source_root=source_root)
    persist_candidate_scores(conn, scores)
    return len(scores)


@app.command()
def query(
    ctx: typer.Context,
    sql: Annotated[str, typer.Argument(help="SQL to run against the repo's index.duckdb.")],
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
) -> None:
    """Run an arbitrary read-only SQL against a cached repo's index."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    db = cache_root / repo_id / "index.duckdb"
    conn = duckdb.connect(str(db), read_only=True)
    try:
        cur = conn.execute(sql)
        columns = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchall()
    finally:
        conn.close()
    typer.echo(_format_rows(columns, rows))


@app.command()
def flows(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    from_symbol: Annotated[str, typer.Option("--from")] = "",
    to_symbol: Annotated[str, typer.Option("--to")] = "",
) -> None:
    """List flows reaching/from a symbol via the navigation views."""
    if bool(from_symbol) == bool(to_symbol):
        typer.echo("Specify exactly one of --from or --to.", err=True)
        raise typer.Exit(code=1)

    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    db = cache_root / repo_id / "index.duckdb"
    conn = duckdb.connect(str(db), read_only=True)
    try:
        if from_symbol:
            cur = conn.execute(
                "SELECT * FROM v_sources_to_sinks WHERE source_symbol_id = ?",
                [from_symbol],
            )
        else:
            cur = conn.execute(
                "SELECT * FROM v_sinks_from_sources WHERE sink_symbol_id = ?",
                [to_symbol],
            )
        columns = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchall()
    finally:
        conn.close()
    if not rows:
        typer.echo("no flows")
        return
    typer.echo(_format_rows(columns, rows))


@app.command("candidates")
def candidates(  # noqa: PLR0913 - Typer command options are intentionally explicit.
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    limit: Annotated[int, typer.Option("--limit", help="Maximum candidates to show.")] = 50,
    all_candidates: Annotated[
        bool,
        typer.Option("--all", help="Show all matching candidates; ignores --limit."),
    ] = False,
    label: Annotated[
        str,
        typer.Option("--label", help="Comma-separated human labels to show."),
    ] = "",
    bucket: Annotated[
        str,
        typer.Option("--bucket", help="Comma-separated processing buckets to show."),
    ] = "",
    stream: Annotated[
        str,
        typer.Option("--stream", help="Filter by stream, for example A or B."),
    ] = "",
    min_score: Annotated[
        float | None,
        typer.Option("--min-score", help="Minimum candidate score to show."),
    ] = None,
) -> None:
    """List scored review candidates for a cached repo."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    db = cache_root / repo_id / "index.duckdb"
    conn = duckdb.connect(str(db), read_only=True)
    try:
        has_scores = conn.execute(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'candidate_scores'"
        ).fetchone()
        if not has_scores or int(has_scores[0]) == 0:
            typer.echo("no scored candidates; run `ai-codescan nominate` first")
            return
        columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info('candidate_scores')").fetchall()
        }
        has_bucket = "processing_bucket" in columns
        rows = conn.execute(
            """
            SELECT candidate_id, label, score, stream, flow_id, factors_json
            FROM candidate_scores
            ORDER BY score DESC, candidate_id
            """
        ).fetchall()
        bucket_rows = (
            conn.execute(
                """
            SELECT candidate_id, processing_bucket
            FROM candidate_scores
            """
            ).fetchall()
            if has_bucket
            else []
        )
    finally:
        conn.close()
    if not rows:
        typer.echo("no scored candidates; run `ai-codescan nominate` first")
        return
    buckets_by_id = {
        str(candidate_id): str(processing_bucket or "")
        for candidate_id, processing_bucket in bucket_rows
    }
    labels = {item.strip() for item in label.split(",") if item.strip()}
    buckets = {item.strip() for item in bucket.split(",") if item.strip()}
    streams = {item.strip().upper() for item in stream.split(",") if item.strip()}
    compact_rows = []
    for raw_candidate_id, raw_label, raw_score, raw_stream, flow_id, factors_json in rows:
        candidate_id = str(raw_candidate_id)
        candidate_label = str(raw_label or "")
        candidate_stream = str(raw_stream or "")
        score_f = float(raw_score or 0.0)
        processing_bucket = buckets_by_id.get(candidate_id) or candidate_label
        if labels and candidate_label not in labels:
            continue
        if buckets and processing_bucket not in buckets:
            continue
        if streams and candidate_stream.upper() not in streams:
            continue
        if min_score is not None and score_f < min_score:
            continue
        try:
            factors = json.loads(factors_json or "[]")
        except json.JSONDecodeError:
            factors = []
        factor_names = ",".join(str(f.get("name", "")) for f in factors if isinstance(f, dict))
        compact_rows.append(
            (
                candidate_id,
                candidate_label,
                processing_bucket,
                round(score_f, 3),
                candidate_stream,
                flow_id or "",
                factor_names,
            )
        )
        if not all_candidates and len(compact_rows) >= limit:
            break
    if not compact_rows:
        typer.echo("no scored candidates matched filters")
        return
    typer.echo(
        _format_rows(
            ["candidate", "label", "bucket", "score", "stream", "flow", "factors"],
            compact_rows,
        )
    )


@app.command("miss-finder")
def miss_finder(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Output JSONL path. Defaults to <repo>/miss_candidates.jsonl."),
    ] = None,
    bundles_dir: Annotated[
        Path | None,
        typer.Option(
            "--bundles-dir",
            help="Directory for exploratory evidence bundles. Defaults to <repo>/miss_bundles.",
        ),
    ] = None,
) -> None:
    """Generate high-recall exploratory candidates from indexed repo context."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    repo_dir = cache_root / repo_id
    db = repo_dir / "index.duckdb"
    if not db.is_file():
        typer.echo(f"No index found for repo {repo_id}; run `ai-codescan prep` first.", err=True)
        raise typer.Exit(code=1)
    out_path = out if out is not None else repo_dir / "miss_candidates.jsonl"
    bundle_output_dir = bundles_dir if bundles_dir is not None else repo_dir / "miss_bundles"
    conn = duckdb.connect(str(db))
    try:
        generated = write_miss_candidates(
            conn,
            out_path=out_path,
            source_root=repo_dir / "source",
            bundles_dir=bundle_output_dir,
            review_state_dir=repo_dir,
        )
    finally:
        conn.close()
    typer.echo(
        f"wrote {len(generated)} miss candidate(s) to {out_path}; bundles at {bundle_output_dir}"
    )


@app.command("miss-review")
def miss_review(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
    llm_provider: Annotated[str, typer.Option("--llm-provider")] = "claude",
    llm_model: Annotated[str, typer.Option("--llm-model")] = "",
    max_candidates: Annotated[
        int,
        typer.Option("--max-candidates", help="Maximum miss candidates to stage."),
    ] = 20,
) -> None:
    """Stage exploratory miss-review work and execute it when an LLM CLI is available."""
    # Local import: ai_codescan.miss_review imports ai_codescan.nominator which
    # transitively reaches the CLI module surface. Importing at function scope
    # keeps cli.py free of the cycle.
    from ai_codescan.miss_review import run_miss_review  # noqa: PLC0415

    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    repo_dir = cache_root / repo_id
    candidates_path = repo_dir / "miss_candidates.jsonl"
    if not candidates_path.is_file():
        typer.echo("No miss_candidates.jsonl. Run `ai-codescan miss-finder` first.", err=True)
        raise typer.Exit(code=1)

    runs_root = repo_dir / "runs"
    if not runs_root.is_dir() or not any(runs_root.iterdir()):
        typer.echo("No runs. Run nominate + gate-1 first.", err=True)
        raise typer.Exit(code=1)
    last_run = max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)

    llm = LLMConfig(provider=llm_provider, model=llm_model or None)
    db_path = repo_dir / "index.duckdb"
    result = run_miss_review(
        candidates_path=candidates_path,
        repo_dir=repo_dir,
        db_path=db_path,
        run_dir=last_run,
        max_candidates=max_candidates,
        llm=llm,
    )
    if not result["executed"]:
        typer.echo(
            f"staged {result['staged']} miss review candidate(s) at {result['queue']}; "
            "LLM unavailable"
        )
        return
    typer.echo(
        f"staged {result['staged']} miss review candidate(s); "
        f"LLM produced {result['reviews']} structured review(s) in "
        f"{repo_dir / 'miss_reviews'}"
    )
    routed_pack = result.get("routed_to_pack", 0)
    routed_joern = result.get("routed_to_joern", 0)
    pending = result.get("pending_custom_rule", 0)
    if routed_pack or routed_joern or pending:
        typer.echo(
            f"triage: {routed_pack} Semgrep pack(s) enabled; "
            f"{routed_joern} Joern extension(s) added; "
            f"{pending} pending custom rule (run `model-proposals apply <id>`)"
        )


@app.command("adversarial-review")
def adversarial_review(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
    challenger: Annotated[
        str,
        typer.Option(
            "--challenger",
            help="LLM provider for the challenger. Pick one DIFFERENT from the "
            "reviewer — cross-model independence is the point.",
        ),
    ] = "gemini",
    challenger_model: Annotated[
        str, typer.Option("--challenger-model", help="Optional challenger model override.")
    ] = "",
    timeout: Annotated[
        int,
        typer.Option(
            "--timeout",
            help="Per-challenge LLM timeout in seconds. Raise it for slow CLIs.",
        ),
    ] = 180,
) -> None:
    """Phase 13: a second, independent LLM challenges each review verdict.

    For every decisive ``review_verdicts`` row, the challenger argues the
    opposite case. Disputed verdicts are recorded in ``adversarial_challenges``
    — nothing is dropped. Disputed false-positives are flagged loudly: a
    reviewer dismissed something a second model thinks is real.
    """
    from ai_codescan.adversarial_validator import (  # noqa: PLC0415
        CHALLENGEABLE_VERDICTS,
        challenge_verdicts,
        load_review_verdicts,
        make_adversarial_challenger,
        persist_adversarial_challenges,
        summarize_challenges,
        with_reachability_evidence,
    )

    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    db_path = cache_root / repo_id / "index.duckdb"
    if not db_path.is_file():
        typer.echo(f"no DuckDB index at {db_path}; run a scan + review first", err=True)
        raise typer.Exit(code=1)

    llm = LLMConfig(provider=challenger, model=challenger_model or None)
    try:
        challenger_fn = make_adversarial_challenger(llm, timeout_seconds=timeout)
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    conn = duckdb.connect(str(db_path))
    try:
        verdicts = load_review_verdicts(conn)
        decisive = [v for v in verdicts if v.verdict in CHALLENGEABLE_VERDICTS]
        if not decisive:
            typer.echo("no decisive review verdicts to challenge (run a review first)")
            return
        # Enrich with a reachability note so the challenger argues with the
        # data-flow-proven vs co-location distinction in hand (audit pillar #5).
        decisive = with_reachability_evidence(conn, decisive)
        challenges = challenge_verdicts(decisive, challenger=challenger_fn)
        persist_adversarial_challenges(conn, challenges)
        # Re-score so a disputed verdict immediately shifts candidate ranking
        # (a disputed dismissal re-elevates; a disputed report demotes).
        _rescore_candidates(conn, source_root=cache_root / repo_id / "source")
    finally:
        conn.close()

    summary = summarize_challenges(challenges)
    typer.echo(
        f"adversarial-review (challenger={challenger}): "
        f"{summary['total']} challenged — "
        f"{summary['confirmed']} confirmed, "
        f"{summary['disputed']} disputed, "
        f"{summary['inconclusive']} inconclusive"
    )
    if summary["disputed_false_positives"]:
        typer.echo(
            f"  ⚠ {summary['disputed_false_positives']} dismissed finding(s) the challenger "
            "thinks are REAL — review `adversarial_challenges` for potential missed bugs",
            err=True,
        )
    if summary["disputed_true_positives"]:
        typer.echo(
            f"  {summary['disputed_true_positives']} reported finding(s) the challenger "
            "thinks are false positives — worth a second look"
        )


@app.command("recon")
def recon(
    ctx: typer.Context,
    target: Annotated[
        Path,
        typer.Argument(help="Path to the original git checkout (for git-history recon)."),
    ] = Path("."),
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
) -> None:
    """Phase 13: nominate sibling files worth a second scan.

    Combines git-history recon (siblings of past security-fix files) with
    the feedback loop (siblings of confirmed findings). Writes
    `recon_hints.jsonl` into the repo cache — the nominator / miss-finder
    can prioritise those files on the next pass. Recall-first: recon only
    ever adds files to look at.
    """
    from ai_codescan.recon import collect_recon_hints, write_recon_hints  # noqa: PLC0415

    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    repo_dir = cache_root / repo_id
    source_root = repo_dir / "source"
    db_path = repo_dir / "index.duckdb"

    conn = duckdb.connect(str(db_path)) if db_path.is_file() else None
    try:
        hints = collect_recon_hints(target, source_root=source_root, conn=conn)
    finally:
        if conn is not None:
            conn.close()
    out_path = write_recon_hints(hints, out_path=repo_dir / "recon_hints.jsonl")
    git_hints = sum(1 for h in hints if h.source == "git-history")
    fb_hints = sum(1 for h in hints if h.source == "feedback-loop")
    typer.echo(
        f"recon: {len(hints)} file(s) to re-hunt "
        f"({git_hints} from git-history, {fb_hints} from the feedback loop) -> {out_path}"
    )


@app.command()
def view(
    ctx: typer.Context,
    file: Annotated[
        str, typer.Option("--file", help="Absolute path of a file in the snapshot.")
    ] = "",
    symbol: Annotated[str, typer.Option("--symbol", help="Symbol id to centre the view on.")] = "",
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
) -> None:
    """Render an annotated source view to stdout."""
    if bool(file) == bool(symbol):
        typer.echo("Specify exactly one of --file or --symbol.", err=True)
        raise typer.Exit(code=1)

    cache_root: Path = ctx.obj["cache_root"]
    if not repo_id:
        repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
        if len(repos) != 1:
            typer.echo("Specify --repo-id.", err=True)
            raise typer.Exit(code=1)
        repo_id = repos[0]
    db_path = cache_root / repo_id / "index.duckdb"
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        if symbol:
            row = conn.execute("SELECT file FROM symbols WHERE id = ?", [symbol]).fetchone()
            if not row:
                typer.echo(f"unknown symbol id: {symbol}", err=True)
                raise typer.Exit(code=1)
            file = row[0]

        typer.echo(
            render_file_view(
                conn,
                file=file,
                source_root=cache_root / repo_id / "source",
            )
        )
    finally:
        conn.close()


@app.command()
def entrypoints(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
) -> None:
    """Print the cached ``entrypoints.md``."""
    cache_root: Path = ctx.obj["cache_root"]
    if not repo_id:
        repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
        if len(repos) != 1:
            typer.echo("Specify --repo-id.", err=True)
            raise typer.Exit(code=1)
        repo_id = repos[0]
    md_path = cache_root / repo_id / "entrypoints.md"
    if not md_path.is_file():
        typer.echo("No entrypoints.md yet — run `prep` first.", err=True)
        raise typer.Exit(code=1)
    typer.echo(md_path.read_text(encoding="utf-8"))


@app.command()
def status(ctx: typer.Context) -> None:
    """Print summary of cached repos and their phase progress."""
    cache_root: Path = ctx.obj["cache_root"]
    if not cache_root.exists():
        typer.echo("No cached repos.")
        return
    repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
    if not repos:
        typer.echo("No cached repos.")
        return
    for name in repos:
        typer.echo(f"- {name}")


@eval_app.command("run")
def eval_run(
    ctx: typer.Context,
    targets: Annotated[
        Path,
        typer.Option(
            "--targets",
            help="Eval manifest file or directory containing manifest.yml.",
        ),
    ] = Path("eval-targets"),
    engine: Annotated[
        str,
        typer.Option(
            "--engine",
            help=(
                "Override manifest engine for every case: hybrid, hybrid-miss, "
                "miss-finder, or joern."
            ),
        ),
    ] = "",
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            help="Output directory for results.jsonl, summary.json, and report.md.",
        ),
    ] = None,
) -> None:
    """Run known-ground-truth eval targets and write machine-readable results."""
    cache_root: Path = ctx.obj["cache_root"]
    cases = load_eval_cases(targets)
    if not cases:
        typer.echo(f"no eval cases found under {targets}", err=True)
        raise typer.Exit(code=1)
    if out is None:
        stamp = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        out = cache_root / "evals" / stamp
    results = [
        run_ai_codescan_case(case, cache_root=cache_root, engine=engine or None) for case in cases
    ]
    results_path = write_eval_outputs(results, out_dir=out)
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    typer.echo(f"wrote {results_path}")
    typer.echo(" ".join(f"{status}={count}" for status, count in sorted(counts.items())))


@eval_app.command("compare")
def eval_compare(
    ai_results: Annotated[
        Path,
        typer.Option("--ai-results", help="ai-codescan results.jsonl or JSON results file."),
    ],
    ghost_results: Annotated[
        Path,
        typer.Option("--ghost-results", help="Imported Ghost JSON/JSONL results."),
    ],
    out: Annotated[
        Path,
        typer.Option("--out", help="Output directory for comparison.jsonl and comparison.md."),
    ] = Path("eval-results/comparison"),
) -> None:
    """Compare ai-codescan eval results with imported Ghost results."""
    ai = load_eval_results(ai_results, scanner="ai-codescan")
    ghost = load_eval_results(ghost_results, scanner="ghost")
    comparisons = compare_eval_results(ai, ghost)
    path = write_eval_comparison(comparisons, out_dir=out)
    counts: dict[str, int] = {}
    for comparison in comparisons:
        counts[comparison.delta] = counts.get(comparison.delta, 0) + 1
    typer.echo(f"wrote {path}")
    typer.echo(" ".join(f"{delta}={count}" for delta, count in sorted(counts.items())))


@model_proposals_app.command("generate")
def model_proposals_generate(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
    language: Annotated[str, typer.Option("--language", help="Optional language hint.")] = "",
    framework: Annotated[str, typer.Option("--framework", help="Optional framework hint.")] = "",
    target_engine: Annotated[
        str,
        typer.Option("--target-engine", help="Target engine for the proposal."),
    ] = "heuristic",
) -> None:
    """Generate proposal JSON files from needs-model-extension verdicts."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    repo_dir = cache_root / repo_id
    db = repo_dir / "index.duckdb"
    if not db.is_file():
        typer.echo("No index. Run prep first.", err=True)
        raise typer.Exit(code=1)
    run_dir = _latest_run_dir(repo_dir)
    conn = duckdb.connect(str(db), read_only=True)
    try:
        proposals = proposals_from_verdicts(
            conn,
            language=language,
            framework=framework,
            target_engine=target_engine,
        )
    finally:
        conn.close()
    paths = write_model_proposals(proposals, proposals_dir=run_dir / "model_proposals")
    typer.echo(f"wrote {len(paths)} proposal(s) to {run_dir / 'model_proposals'}")


@model_proposals_app.command("list")
def model_proposals_list(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
) -> None:
    """List model-extension proposals for the latest run."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    run_dir = _latest_run_dir(cache_root / repo_id)
    proposals = list_model_proposals(run_dir / "model_proposals")
    rows = [
        (
            proposal.proposal_id,
            proposal.cwe,
            proposal.bug_class,
            proposal.target_engine,
            proposal.nomination_id,
        )
        for proposal in proposals
    ]
    typer.echo(_format_rows(["proposal", "cwe", "class", "engine", "nomination"], rows))


@model_proposals_app.command("accept")
def model_proposals_accept(  # noqa: PLR0913 - Typer command surface; each arg is a CLI flag
    ctx: typer.Context,
    proposal_id: Annotated[str, typer.Argument(help="Proposal id to accept.")],
    eval_target: Annotated[
        Path,
        typer.Option("--eval-target", help="Existing eval target required for acceptance."),
    ],
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
    apply: Annotated[
        bool,
        typer.Option("--apply", help="Record a non-dry-run acceptance marker."),
    ] = False,
    require_paired_targets: Annotated[
        bool,
        typer.Option(
            "--require-paired-targets",
            help="Enforce Phase 3 paired-target gate (Invariant 5).",
        ),
    ] = False,
) -> None:
    """Dry-run accept a proposal after checking that a regression target exists."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    run_dir = _latest_run_dir(cache_root / repo_id)
    proposal_path = run_dir / "model_proposals" / f"{proposal_id}.json"
    if not proposal_path.is_file():
        typer.echo(f"unknown proposal: {proposal_id}", err=True)
        raise typer.Exit(code=1)
    proposal = list_model_proposals(proposal_path.parent)
    by_id = {item.proposal_id: item for item in proposal}
    try:
        result = accept_model_proposal(
            by_id[proposal_id],
            eval_target=eval_target,
            dry_run=not apply,
            require_paired_targets=require_paired_targets,
        )
    except (KeyError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(result, sort_keys=True))


@model_proposals_app.command("link-targets")
def model_proposals_link_targets(
    ctx: typer.Context,
    proposal_id: Annotated[str, typer.Argument(help="Proposal id to update.")],
    positive: Annotated[Path, typer.Option("--positive", help="Path to a positive eval target.")],
    negative: Annotated[Path, typer.Option("--negative", help="Path to a negative eval target.")],
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
) -> None:
    """Attach paired positive + negative eval targets to a proposal (Phase 3 Invariant 5)."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    run_dir = _latest_run_dir(cache_root / repo_id)
    proposals_dir = run_dir / "model_proposals"
    proposal_path = proposals_dir / f"{proposal_id}.json"
    if not proposal_path.is_file():
        typer.echo(f"unknown proposal: {proposal_id}", err=True)
        raise typer.Exit(code=1)
    proposals = list_model_proposals(proposals_dir)
    by_id = {p.proposal_id: p for p in proposals}
    try:
        updated = link_eval_targets(
            by_id[proposal_id],
            positive=positive,
            negative=negative,
            proposals_dir=proposals_dir,
        )
    except (KeyError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    db_path = cache_root / repo_id / "index.duckdb"
    if db_path.is_file():
        conn = duckdb.connect(str(db_path))
        try:
            apply_schema(conn)
            record_proposal_decision(
                conn,
                proposal_id=updated.proposal_id,
                decision="pending",
                eval_positive=updated.eval_positive,
                eval_negative=updated.eval_negative,
            )
        finally:
            conn.close()
    typer.echo(
        f"linked: {updated.proposal_id} positive={updated.eval_positive} "
        f"negative={updated.eval_negative}"
    )


@model_proposals_app.command("apply")
def model_proposals_apply(  # noqa: PLR0912, PLR0913, PLR0915 - Typer command surface + three-engine dispatch
    ctx: typer.Context,
    proposal_id: Annotated[str, typer.Argument(help="Proposal id to apply.")],
    engine: Annotated[
        str, typer.Option("--engine", help="Engine target: semgrep | joern | codeql.")
    ] = "semgrep",
    rules_root: Annotated[
        Path,
        typer.Option(
            "--rules-root",
            help=(
                "Rules root dir; defaults to the repo cache's .semgrep/ and lands under "
                "rules.staged/."
            ),
        ),
    ] = Path(".semgrep"),
    promote: Annotated[
        bool,
        typer.Option(
            "--promote",
            help="Write directly into the active rules/ dir instead of rules.staged/.",
        ),
    ] = False,
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
) -> None:
    """Render a Semgrep YAML rule from a proposal. Stages by default (Phase 7 dry-run gate)."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    run_dir = _latest_run_dir(cache_root / repo_id)
    proposal_path = run_dir / "model_proposals" / f"{proposal_id}.json"
    if not proposal_path.is_file():
        typer.echo(f"unknown proposal: {proposal_id}", err=True)
        raise typer.Exit(code=1)
    proposals = list_model_proposals(proposal_path.parent)
    by_id = {p.proposal_id: p for p in proposals}
    proposal = by_id.get(proposal_id)
    if proposal is None:
        typer.echo(f"unknown proposal: {proposal_id}", err=True)
        raise typer.Exit(code=1)
    # Enforce paired-target gate before any rule generation.
    if not (proposal.eval_positive and proposal.eval_negative):
        typer.echo(
            "paired-target gate: link both positive AND negative eval targets first "
            "(`ai-codescan model-proposals link-targets ...`).",
            err=True,
        )
        raise typer.Exit(code=1)
    if engine == "joern":
        # Phase 5: Joern model patching. The extension JSON lives in the
        # repo cache; the Joern script reads it via AICS_JOERN_EXTENSIONS
        # at scan time. Phase 5.1: staged-by-default (writes to the
        # .staged.json sibling). `--promote` writes to the active file
        # Joern reads at scan time. Mirrors Semgrep's rules.staged/ vs
        # rules/ distinction.
        from ai_codescan.joern_extensions import (  # noqa: PLC0415
            apply_proposal_to_joern,
            staged_path_for,
        )

        ext_path = cache_root / repo_id / "aics-joern-extension-packs.json"
        try:
            entry = apply_proposal_to_joern(
                proposal,
                extension_path=ext_path,
                staged=not promote,
            )
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        written_path = ext_path if promote else staged_path_for(ext_path)
        db_path = cache_root / repo_id / "index.duckdb"
        if db_path.is_file():
            conn = duckdb.connect(str(db_path))
            try:
                apply_schema(conn)
                record_proposal_decision(
                    conn,
                    proposal_id=proposal.proposal_id,
                    decision="applied",
                    engine=f"joern-extension:{entry.sink_class}",
                    eval_positive=proposal.eval_positive,
                    eval_negative=proposal.eval_negative,
                    applied_path=str(written_path),
                )
            finally:
                conn.close()
        typer.echo(
            f"wrote {'promoted' if promote else 'staged'} Joern extension sink "
            f"(language={entry.language} cwe={entry.cwe} pattern={entry.pattern}): {written_path}"
        )
        return
    if engine == "codeql":
        # Phase 10: CodeQL pack extension wiring. Parallel to the Joern
        # branch above — proposals routed via ``target_engine="codeql"``
        # land in a JSON sidecar that the YAML renderer emits at scan
        # time. Staged-by-default; ``--promote`` writes to the active
        # file the renderer reads. The CLI does not auto-run the YAML
        # renderer — users opt in by setting
        # ``AICS_CODEQL_EXTENSIONS_DIR`` and passing
        # ``--additional-packs`` to `codeql database analyze`.
        from ai_codescan.codeql_extensions import (  # noqa: I001, PLC0415
            apply_proposal_to_codeql,
            staged_path_for as codeql_staged_path_for,
        )

        ext_path = cache_root / repo_id / "aics-codeql-extension-packs.json"
        try:
            codeql_entry = apply_proposal_to_codeql(
                proposal,
                extension_path=ext_path,
                staged=not promote,
            )
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        written_path = ext_path if promote else codeql_staged_path_for(ext_path)
        db_path = cache_root / repo_id / "index.duckdb"
        if db_path.is_file():
            conn = duckdb.connect(str(db_path))
            try:
                apply_schema(conn)
                record_proposal_decision(
                    conn,
                    proposal_id=proposal.proposal_id,
                    decision="applied",
                    engine=f"codeql-extension:{codeql_entry.language}",
                    eval_positive=proposal.eval_positive,
                    eval_negative=proposal.eval_negative,
                    applied_path=str(written_path),
                )
            finally:
                conn.close()
        typer.echo(
            f"wrote {'promoted' if promote else 'staged'} CodeQL extension sink "
            f"(language={codeql_entry.language} cwe={codeql_entry.cwe} "
            f"method={codeql_entry.method_name}): {written_path}"
        )
        return
    if engine != "semgrep":
        typer.echo(
            f"engine '{engine}' not supported (try semgrep, joern, or codeql).",
            err=True,
        )
        raise typer.Exit(code=1)
    repo_dir = cache_root / repo_id
    effective_rules_root = repo_dir / ".semgrep" if rules_root == Path(".semgrep") else rules_root
    rule_path = apply_proposal_to_semgrep(
        proposal,
        rules_root=effective_rules_root,
        staged=not promote,
    )
    if promote:
        register_rules_root(repo_dir, effective_rules_root)
    db_path = cache_root / repo_id / "index.duckdb"
    if db_path.is_file():
        conn = duckdb.connect(str(db_path))
        try:
            apply_schema(conn)
            record_proposal_decision(
                conn,
                proposal_id=proposal.proposal_id,
                decision="applied",
                engine=engine,
                eval_positive=proposal.eval_positive,
                eval_negative=proposal.eval_negative,
                applied_path=str(rule_path),
            )
        finally:
            conn.close()
    typer.echo(f"wrote {'promoted' if promote else 'staged'} Semgrep rule: {rule_path}")


@model_proposals_app.command("promote")
def model_proposals_promote(
    ctx: typer.Context,
    proposal_id: Annotated[
        str,
        typer.Argument(help="Proposal id to promote (ignored when --all is set)."),
    ] = "",
    engine: Annotated[
        str,
        typer.Option(
            "--engine",
            help="Which engine's staged area to promote from (currently: joern).",
        ),
    ] = "joern",
    all_staged: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Promote every staged Joern extension at once.",
        ),
    ] = False,
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
) -> None:
    """Promote staged Joern extensions into the active file Joern reads."""
    if engine != "joern":
        typer.echo(
            f"engine '{engine}' has no separate staged/promoted distinction; "
            "only 'joern' supports promote.",
            err=True,
        )
        raise typer.Exit(code=1)
    from ai_codescan.joern_extensions import (  # noqa: PLC0415
        load_joern_extensions,
        promote_joern_extension,
        staged_path_for,
    )

    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    ext_path = cache_root / repo_id / "aics-joern-extension-packs.json"
    if all_staged:
        staged_entries = load_joern_extensions(staged_path_for(ext_path))
        if not staged_entries:
            typer.echo("no staged Joern extensions to promote")
            return
        promoted_ids: list[str] = []
        for entry in staged_entries:
            if not entry.proposal_id:
                continue
            moved = promote_joern_extension(entry.proposal_id, extension_path=ext_path)
            if moved is not None:
                promoted_ids.append(moved.proposal_id)
        typer.echo(
            f"promoted {len(promoted_ids)} Joern extension(s) into {ext_path}: "
            + ", ".join(promoted_ids)
        )
        return
    if not proposal_id:
        typer.echo("must pass a proposal id or --all", err=True)
        raise typer.Exit(code=1)
    moved = promote_joern_extension(proposal_id, extension_path=ext_path)
    if moved is None:
        typer.echo(f"no staged Joern extension found for proposal {proposal_id}", err=True)
        raise typer.Exit(code=1)
    typer.echo(
        f"promoted Joern extension (proposal={proposal_id} pattern={moved.pattern}) into {ext_path}"
    )


@model_proposals_app.command("clone")
def model_proposals_clone(  # noqa: PLR0913 - Typer command surface
    ctx: typer.Context,
    proposal_id: Annotated[str, typer.Argument(help="Proposal id to clone.")],
    engine: Annotated[
        str,
        typer.Option(
            "--engine",
            help="target_engine for the clone (e.g. joern, semgrep).",
        ),
    ],
    rewrite_with_llm: Annotated[
        bool,
        typer.Option(
            "--rewrite-with-llm",
            help=(
                "Phase 7: call the configured LLM to translate sink_pattern "
                "for the new engine. Falls back to keeping the source pattern "
                "if the LLM is unavailable or fails."
            ),
        ),
    ] = False,
    llm_provider: Annotated[str, typer.Option("--llm-provider")] = "claude",
    llm_model: Annotated[str, typer.Option("--llm-model")] = "",
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
) -> None:
    """Clone a proposal into a sibling targeting a different engine.

    The new proposal id is the original id + ``-<engine>``; same content
    otherwise. This is the multi-engine path — instead of a "both" mode
    that muddies the schema, the user runs ``apply`` on each sibling
    independently. Provenance to the source proposal is preserved via the
    rationale prefix.
    """
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    run_dir = _latest_run_dir(cache_root / repo_id)
    proposals_dir = run_dir / "model_proposals"
    proposals = list_model_proposals(proposals_dir)
    by_id = {p.proposal_id: p for p in proposals}
    if proposal_id not in by_id:
        typer.echo(f"unknown proposal: {proposal_id}", err=True)
        raise typer.Exit(code=1)
    source = by_id[proposal_id]
    if (source.target_engine or "").lower() == engine.lower():
        typer.echo(
            f"proposal {proposal_id} already targets engine '{engine}'; nothing to clone",
            err=True,
        )
        raise typer.Exit(code=1)
    from ai_codescan.model_proposals import ModelProposal, write_model_proposals  # noqa: PLC0415

    cloned_id = f"{source.proposal_id}-{engine.lower()}"
    if cloned_id in by_id:
        typer.echo(f"clone already exists: {cloned_id}", err=True)
        raise typer.Exit(code=1)
    # Phase 7: optionally rewrite sink_pattern via LLM. When the LLM is
    # unavailable or fails the original pattern is preserved (the user
    # edits before apply, same as the no-LLM clone path).
    rewritten_sink = source.sink_pattern
    if rewrite_with_llm and source.sink_pattern:
        try:
            from ai_codescan.proposal_clone_rewrite import (  # noqa: PLC0415
                make_llm_rewriter,
            )

            llm_cfg = LLMConfig(provider=llm_provider, model=llm_model or None)
            rewriter = make_llm_rewriter(llm_cfg)
            translated = rewriter(
                sink_pattern=source.sink_pattern,
                source_engine=source.target_engine,
                target_engine=engine.lower(),
                language=source.language,
                cwe=source.cwe,
            )
            if translated:
                rewritten_sink = translated
        except RuntimeError as exc:
            typer.echo(
                f"warning: LLM rewriter unavailable ({exc}); cloning with original sink_pattern",
                err=True,
            )
    cloned = ModelProposal(
        proposal_id=cloned_id,
        nomination_id=source.nomination_id,
        finding_id=source.finding_id,
        verdict=source.verdict,
        cwe=source.cwe,
        language=source.language,
        framework=source.framework,
        bug_class=source.bug_class,
        source_pattern=source.source_pattern,
        sink_pattern=rewritten_sink,
        sanitizer_pattern=source.sanitizer_pattern,
        vulnerable_example=source.vulnerable_example,
        safe_example=source.safe_example,
        target_engine=engine.lower(),
        eval_target=source.eval_target,
        rationale=f"clone of {source.proposal_id} for engine={engine}; {source.rationale}",
        source_path=source.source_path,
        eval_positive=source.eval_positive,
        eval_negative=source.eval_negative,
        receiver_regex=source.receiver_regex,
    )
    write_model_proposals([cloned], proposals_dir=proposals_dir)
    typer.echo(f"cloned: {source.proposal_id} -> {cloned_id} (target_engine={engine.lower()})")


@model_proposals_app.command("reject")
def model_proposals_reject(
    ctx: typer.Context,
    proposal_id: Annotated[str, typer.Argument(help="Proposal id to reject.")],
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
) -> None:
    """Mark a proposal as rejected — recorded in proposal_decisions."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    db_path = cache_root / repo_id / "index.duckdb"
    if not db_path.is_file():
        typer.echo(f"no DuckDB index at {db_path}", err=True)
        raise typer.Exit(code=1)
    conn = duckdb.connect(str(db_path))
    try:
        apply_schema(conn)
        record_proposal_decision(conn, proposal_id=proposal_id, decision="rejected")
    finally:
        conn.close()
    typer.echo(f"rejected: {proposal_id}")


@model_proposals_app.command("status")
def model_proposals_status(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
) -> None:
    """Print pending/applied/rejected counts from `proposal_decisions`."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    db_path = cache_root / repo_id / "index.duckdb"
    if not db_path.is_file():
        typer.echo("pending=0 applied=0 rejected=0  (no DuckDB index)")
        return
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        counts = proposal_decision_counts(conn)
    finally:
        conn.close()
    typer.echo(
        f"pending={counts['pending']} applied={counts['applied']} rejected={counts['rejected']}"
    )


def _human_size(bytes_: int) -> str:
    size = float(bytes_)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < _BYTES_PER_KIB or unit == "GiB":
            return f"{size:>6.1f} {unit}"
        size /= _BYTES_PER_KIB
    raise AssertionError("unreachable")


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file() and not p.is_symlink():
            with contextlib.suppress(OSError):
                total += p.stat().st_size
    return total


@cache_app.command("list")
def cache_list(ctx: typer.Context) -> None:
    """List cached repos with size + age."""
    cache_root: Path = ctx.obj["cache_root"]
    if not cache_root.exists():
        typer.echo("No cached repos.")
        return
    repos = sorted(p for p in cache_root.iterdir() if p.is_dir())
    if not repos:
        typer.echo("No cached repos.")
        return
    for repo_dir in repos:
        size = _dir_size(repo_dir)
        mtime = _dt.datetime.fromtimestamp(repo_dir.stat().st_mtime, tz=_dt.UTC)
        typer.echo(f"{repo_dir.name}  {_human_size(size)}  {mtime.isoformat(timespec='seconds')}")


@cache_app.command("rm")
def cache_rm(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Argument(help="Repo id to remove.")],
) -> None:
    """Remove a cached repo by id."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_dir = cache_root / repo_id
    if not repo_dir.exists():
        typer.echo(f"Not found: {repo_id}", err=True)
        raise typer.Exit(code=1)

    shutil.rmtree(repo_dir, onexc=force_remove)
    typer.echo(f"Removed {repo_id}")


@cache_app.command("gc")
def cache_gc(ctx: typer.Context) -> None:
    """Stub — Phase 1B will implement stale-snapshot collection."""
    typer.echo("cache gc not implemented yet")


def _build_llm_config(provider: str, model: str) -> LLMConfig:
    """Build :class:`LLMConfig` from CLI flags, exiting cleanly on bad input."""
    try:
        return LLMConfig(provider=provider, model=model or None)
    except UnknownProviderError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def nominate(  # noqa: PLR0913 - flag plumbing matches user-visible CLI surface
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    target_bug_class: Annotated[str, typer.Option("--target-bug-class")] = "",
    temperature: Annotated[float, typer.Option("--temperature")] = 0.0,
    llm_provider: Annotated[
        str,
        typer.Option(
            "--llm-provider",
            help="LLM CLI to invoke: claude, gemini, or codex.",
        ),
    ] = "claude",
    llm_model: Annotated[
        str,
        typer.Option("--llm-model", help="Specific model name passed to the LLM CLI."),
    ] = "",
    run_id: Annotated[
        str,
        typer.Option(
            "--run-id",
            help="Stable run id used to resume a matching nomination attempt.",
        ),
    ] = "",
) -> None:
    """Run the wide-pass nominator skill against the cached repo."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    repo_dir = cache_root / repo_id
    db_path = repo_dir / "index.duckdb"
    if not db_path.is_file():
        typer.echo("No prep output. Run `ai-codescan prep` first.", err=True)
        raise typer.Exit(code=1)

    if target_bug_class:
        try:
            bug_classes = resolve_classes(
                [t.strip() for t in target_bug_class.split(",") if t.strip()]
            )
        except UnknownBugClassError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from exc
    else:
        bug_classes = list_classes()

    llm = _build_llm_config(llm_provider, llm_model)
    try:
        state = load_or_create(
            repo_dir,
            engine="codeql",
            temperature=temperature,
            target_bug_classes=[c.name for c in bug_classes],
            run_id=run_id or None,
            llm_provider=llm.provider,
            llm_model=llm.model,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    nominations_path = run_nominator(
        state, repo_dir=repo_dir, bug_classes=bug_classes, db_path=db_path, llm=llm
    )
    llm_label = f"{llm.provider}{':' + llm.model if llm.model else ''}"
    typer.echo(f"nominations at {nominations_path} (llm: {llm_label})")


@app.command("gate-1")
def gate_1(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    yes: Annotated[bool, typer.Option("--yes", help="Mark every unanswered y/n: as y.")] = False,
    apply: Annotated[
        bool,
        typer.Option("--apply", help="Apply Stream C accepted extensions and re-run CodeQL."),
    ] = False,
) -> None:
    """Open the latest nominations.md for HITL editing, or apply --yes / --apply."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    runs_root = cache_root / repo_id / "runs"
    if not runs_root.is_dir():
        typer.echo("No runs.", err=True)
        raise typer.Exit(code=1)
    last_run = max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)
    nominations = last_run / "nominations.md"
    if not nominations.is_file():
        typer.echo("No nominations.md — run `nominate` first.", err=True)
        raise typer.Exit(code=1)

    if yes:
        nominations.write_text(
            apply_yes_to_all(nominations.read_text(encoding="utf-8")),
            encoding="utf-8",
        )
        typer.echo("marked all unanswered as y")
        return

    if apply:
        exts = selected_extensions(nominations.read_text(encoding="utf-8"))
        if not exts:
            typer.echo("no Stream C extensions accepted")
            return
        ext_dir = cache_root / repo_id / "codeql" / "extensions"
        ext_dir.mkdir(parents=True, exist_ok=True)
        for ext in exts:
            (ext_dir / f"{ext.nomination_id}.model.yml").write_text(
                ext.yaml_body,
                encoding="utf-8",
            )
        conn = duckdb.connect(str(cache_root / repo_id / "index.duckdb"))
        try:
            for db in (cache_root / repo_id / "codeql").glob("*.db"):
                project_id = db.name[:-3]
                try:
                    result = run_queries(
                        db,
                        cache_dir=cache_root / repo_id,
                        project_id=project_id,
                        codeql_tags=[],
                        extension_packs=[ext_dir],
                    )
                    ingest_sarif(
                        conn,
                        sarif_path=result.sarif_path,
                        project_id=project_id,
                        snapshot_root=cache_root / repo_id / "source",
                        engine="codeql",
                    )
                except (RuntimeError, OSError) as exc:
                    typer.echo(f"warning: re-run failed for {project_id}: {exc}", err=True)
        finally:
            conn.close()
        typer.echo(f"applied {len(exts)} extension(s); flows updated")
        return

    editor = os.environ.get("EDITOR", "vi")
    subprocess.run(  # noqa: S603 - editor is user-controlled, no shell
        [editor, str(nominations)],  # noqa: S607
        check=False,
    )


@app.command()
def run(  # noqa: PLR0913 - flag plumbing matches user-visible CLI surface
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Target repo to scan end-to-end.")],
    target_bug_class: Annotated[str, typer.Option("--target-bug-class")] = "",
    temperature: Annotated[float, typer.Option("--temperature")] = 0.0,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Auto-confirm every interactive prompt (LLM choice, HITL gates, "
            "zero-output retries, rate-limit handling).",
        ),
    ] = False,
    commit: _CommitOption = None,
    llm_provider: Annotated[
        str | None,
        typer.Option("--llm-provider", help="LLM CLI: claude, gemini, or codex."),
    ] = None,
    llm_model: Annotated[
        str | None,
        typer.Option("--llm-model", help="Specific model passed through to the LLM CLI."),
    ] = None,
    phases: Annotated[
        str,
        typer.Option(
            "--phases",
            help=(
                "Comma-separated subset of stages to run "
                f"(default: all of {','.join(PIPELINE_STAGES)})."
            ),
        ),
    ] = "",
    start_at: Annotated[
        str,
        typer.Option(
            "--from",
            help="Start the pipeline at this stage (inclusive). Ignored when --phases is set.",
        ),
    ] = "",
    stop_at: Annotated[
        str,
        typer.Option(
            "--to",
            help="Stop after this stage (inclusive). Ignored when --phases is set.",
        ),
    ] = "",
    no_sandbox: Annotated[
        bool,
        typer.Option(
            "--no-sandbox",
            help="Forwarded to the validate stage; runs PoCs without the container sandbox.",
        ),
    ] = False,
    bugbounty: Annotated[
        bool,
        typer.Option(
            "--bugbounty",
            help="Forwarded to the report stage; writes reports under <cwd>/report/.",
        ),
    ] = False,
    engine: Annotated[
        str,
        typer.Option(
            "--engine",
            help=(
                "Static engine for the prep stage: 'hybrid' (CodeQL + Semgrep + Joern, "
                "deduped — recommended), 'codeql', or 'llm-heavy'."
            ),
        ),
    ] = "hybrid",
) -> None:
    """End-to-end pipeline driver.

    Runs ``prep → nominate → gate-1 → analyze → gate-2 → validate →
    gate-3 → report`` in one shot.
    Re-running the same target resumes after the last completed stage
    (state lives at ``<cache>/<repo_id>/run.state.json``). Use ``--phases``
    or ``--from``/``--to`` to slice the pipeline; ``--yes`` runs unattended.

    Scan trusted source only: the prep stage may execute target build tooling
    through SCIP and CodeQL outside a sandbox.
    """
    cache_root: Path = ctx.obj["cache_root"]

    try:
        wanted_phases = select_phases(phases=phases, start_at=start_at, stop_at=stop_at)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    provider_override, model_override = preflight_llm_choice(
        provider_supplied=llm_provider is not None,
        model_supplied=llm_model is not None,
        yes=yes,
    )
    resolved_provider = provider_override or llm_provider or "claude"
    resolved_model = model_override or llm_model or ""

    repo_id = compute_repo_id(target)
    rc = drive_pipeline(
        DriveOptions(
            cache_root=cache_root,
            target=target,
            repo_id=repo_id,
            phases=wanted_phases,
            llm_provider=resolved_provider,
            llm_model=resolved_model,
            temperature=temperature,
            target_bug_class=target_bug_class,
            commit=commit or "",
            yes=yes,
            no_sandbox=no_sandbox,
            bugbounty=bugbounty,
            engine=engine,
        )
    )
    if rc != 0:
        raise typer.Exit(code=rc)


@app.command()
def analyze(  # noqa: PLR0913 - Typer command options are intentionally explicit.
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    llm_provider: Annotated[str, typer.Option("--llm-provider")] = "claude",
    llm_model: Annotated[str, typer.Option("--llm-model")] = "",
    temperature: Annotated[float, typer.Option("--temperature")] = 0.0,
    max_llm_candidates: Annotated[
        int | None,
        typer.Option(
            "--max-llm-candidates",
            "--max-candidates",
            help="Maximum accepted candidates to send to LLM analysis.",
        ),
    ] = None,
    max_bundle_bytes: Annotated[
        int | None,
        typer.Option(
            "--max-bundle-bytes",
            help="Skip LLM analysis for candidates whose evidence bundle exceeds this size.",
        ),
    ] = None,
    min_score: Annotated[
        float,
        typer.Option(
            "--min-score",
            help="Minimum candidate score for LLM analysis; unscored candidates are kept.",
        ),
    ] = 0.0,
    deterministic_only: Annotated[
        bool,
        typer.Option(
            "--deterministic-only",
            help="Stage queue and bundles, then skip LLM analysis even if an LLM CLI is available.",
        ),
    ] = False,
    skip_miss_review: Annotated[
        bool,
        typer.Option(
            "--skip-miss-review",
            help=(
                "Phase 8: by default, analyze auto-invokes miss-finder + miss-review "
                "at the end so the user gets exploratory verdicts in one command. "
                "Pass this flag to keep the old two-step workflow."
            ),
        ),
    ] = False,
    miss_review_max_candidates: Annotated[
        int,
        typer.Option(
            "--miss-review-max-candidates",
            help="When auto-invoking miss-review, cap the queue at this many candidates.",
        ),
    ] = 20,
) -> None:
    """Run the deep-analyzer skill against accepted nominations."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    repo_dir = cache_root / repo_id
    db_path = repo_dir / "index.duckdb"
    if not db_path.is_file():
        typer.echo("No index. Run prep first.", err=True)
        raise typer.Exit(code=1)
    runs_root = repo_dir / "runs"
    if not runs_root.is_dir() or not any(runs_root.iterdir()):
        typer.echo("No runs. Run nominate + gate-1 first.", err=True)
        raise typer.Exit(code=1)
    last_run = max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)
    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=temperature,
        target_bug_classes=[],
        run_id=last_run.name,
        llm_provider=llm_provider,
        llm_model=llm_model or None,
    )
    llm = _build_llm_config(llm_provider, llm_model)
    queue = run_analyzer(
        state,
        repo_dir=repo_dir,
        db_path=db_path,
        llm=llm,
        limits=ReviewLimits(
            min_score=min_score,
            max_candidates=max_llm_candidates,
            max_bundle_bytes=max_bundle_bytes,
            deterministic_only=deterministic_only,
        ),
    )
    typer.echo(f"queue at {queue}")
    # Phase 8: auto-invoke the miss-finder + miss-review tail so the
    # single `analyze` command produces both deep-analyzer findings AND
    # exploratory miss-review verdicts. Skip when --skip-miss-review is
    # passed or when --deterministic-only was set (no LLM to invoke).
    if skip_miss_review or deterministic_only:
        return
    candidates_path = repo_dir / "miss_candidates.jsonl"
    # Always rebuild from the current index. Reusing an old JSONL after a new
    # prep silently hides newly introduced source shapes and newly installed
    # miss-finder rules.
    typer.echo("[miss-review] refreshing miss candidates from the current index")
    conn = duckdb.connect(str(db_path))
    try:
        write_miss_candidates(
            conn,
            out_path=candidates_path,
            source_root=repo_dir / "source",
            bundles_dir=repo_dir / "miss_bundles",
            max_bundles=miss_review_max_candidates,
            review_state_dir=repo_dir,
        )
    finally:
        conn.close()
    from ai_codescan.miss_review import run_miss_review  # noqa: PLC0415

    result = run_miss_review(
        candidates_path=candidates_path,
        repo_dir=repo_dir,
        db_path=db_path,
        run_dir=last_run,
        max_candidates=miss_review_max_candidates,
        llm=llm,
    )
    if result.get("executed"):
        typer.echo(
            f"[miss-review] {result['reviews']} structured review(s); "
            f"triage: {result.get('routed_to_pack', 0)} Semgrep pack(s), "
            f"{result.get('routed_to_joern', 0)} Joern extension(s), "
            f"{result.get('routed_to_codeql', 0)} CodeQL extension(s), "
            f"{result.get('pending_custom_rule', 0)} pending custom rule(s)"
        )
    else:
        typer.echo(f"[miss-review] staged {result['staged']} candidate(s); LLM unavailable")


@app.command("gate-2")
def gate_2(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    yes: Annotated[bool, typer.Option("--yes")] = False,
) -> None:
    """Open findings/ for HITL pruning, or --yes to keep all 'unverified' as-is."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    runs_root = cache_root / repo_id / "runs"
    last_run = max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)
    findings_dir = last_run / "findings"
    if not findings_dir.is_dir():
        typer.echo("No findings dir. Run analyze first.", err=True)
        raise typer.Exit(code=1)
    if yes:
        typer.echo(f"keeping all findings under {findings_dir} as-is")
        return
    editor = os.environ.get("EDITOR", "vi")
    subprocess.run(  # noqa: S603 - editor is user-controlled, no shell
        [editor, str(findings_dir)],  # noqa: S607
        check=False,
    )


@app.command()
def validate(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    no_sandbox: Annotated[bool, typer.Option("--no-sandbox")] = False,
    llm_provider: Annotated[str, typer.Option("--llm-provider")] = "claude",
    llm_model: Annotated[str, typer.Option("--llm-model")] = "",
) -> None:
    """Run the validator skill: PoC author + sandbox executor + status flip."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    repo_dir = cache_root / repo_id
    runs_root = repo_dir / "runs"
    if not runs_root.is_dir() or not any(runs_root.iterdir()):
        typer.echo("No runs.", err=True)
        raise typer.Exit(code=1)
    last_run = max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)
    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=0.0,
        target_bug_classes=[],
        run_id=last_run.name,
        llm_provider=llm_provider,
        llm_model=llm_model or None,
    )
    llm = _build_llm_config(llm_provider, llm_model)
    log_path = run_validator(state, repo_dir=repo_dir, llm=llm, no_sandbox=no_sandbox)
    typer.echo(f"validation log at {log_path}")


@app.command("gate-3")
def gate_3(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    yes: Annotated[bool, typer.Option("--yes")] = False,
) -> None:
    """Print verified findings for sign-off, or auto-confirm with --yes."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    runs_root = cache_root / repo_id / "runs"
    last_run = max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)
    findings_dir = last_run / "findings"
    if not findings_dir.is_dir():
        typer.echo("No findings dir. Run validate first.", err=True)
        raise typer.Exit(code=1)
    verified: list[Path] = []
    for fp in sorted(findings_dir.glob("*.md")):
        f = parse_finding(fp.read_text(encoding="utf-8"))
        if f.status == "verified":
            verified.append(fp)
    if yes:
        typer.echo(f"signed off on {len(verified)} verified finding(s)")
        return
    typer.echo(f"verified findings ({len(verified)}):")
    for fp in verified:
        typer.echo(f"  - {fp}")


@app.command()
def report(  # noqa: PLR0912, PLR0913, PLR0915 - Typer option surface + per-finding render loop
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    report_dir: Annotated[
        Path | None,
        typer.Option(
            "--report-dir",
            help="Where to write the markdown reports (default: ./report/).",
        ),
    ] = None,
    bugbounty: Annotated[
        bool,
        typer.Option(
            "--bugbounty",
            help="Drop reports under <target>/report/ per Bugbounty/CLAUDE.md convention.",
        ),
    ] = False,
    include_candidate_audit: Annotated[
        bool,
        typer.Option(
            "--include-candidate-audit",
            help="Write candidate-audit.md with scored candidates beside reports.",
        ),
    ] = False,
    html: Annotated[
        bool,
        typer.Option(
            "--html",
            help="Also write a self-contained HTML report (report.html + graph pages).",
        ),
    ] = False,
) -> None:
    """Render verified findings as bug-bounty-ready markdown reports."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    runs_root = cache_root / repo_id / "runs"
    last_run = max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)
    findings_dir = last_run / "findings"
    if not findings_dir.is_dir():
        typer.echo("No findings dir. Run validate first.", err=True)
        raise typer.Exit(code=1)

    out_dir = report_dir if report_dir is not None else Path.cwd() / "report"
    if bugbounty:
        # Bugbounty mode reuses ./report/ at CWD per workspace convention.
        out_dir = Path.cwd() / "report"

    written = 0
    verified_findings: list[Finding] = []
    db_path = cache_root / repo_id / "index.duckdb"
    for fp in sorted(findings_dir.glob("*.md")):
        f = parse_finding(fp.read_text(encoding="utf-8"))
        if f.status != "verified":
            continue
        verified_findings.append(f)
        bundle = None
        bundle_path = last_run / "bundles" / f"{f.nomination_id}.json"
        if bundle_path.is_file():
            bundle = evidence_bundle_from_jsonable(
                json.loads(bundle_path.read_text(encoding="utf-8"))
            )
        review_verdict = None
        if db_path.is_file():
            conn = duckdb.connect(str(db_path), read_only=True)
            try:
                has_verdicts = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM information_schema.tables
                    WHERE table_name = 'review_verdicts'
                    """
                ).fetchone()
                if has_verdicts and int(has_verdicts[0]) > 0:
                    row = conn.execute(
                        """
                        SELECT verdict, confidence, reviewer
                        FROM review_verdicts
                        WHERE nomination_id = ?
                        """,
                        [f.nomination_id],
                    ).fetchone()
                    if row:
                        review_verdict = {
                            "verdict": row[0],
                            "confidence": row[1],
                            "reviewer": row[2],
                        }
            finally:
                conn.close()
        target = write_report(
            f,
            report_dir=out_dir,
            bundle=bundle,
            review_verdict=review_verdict,
        )
        typer.echo(f"wrote {target}")
        written += 1
    if include_candidate_audit and db_path.is_file():
        conn = duckdb.connect(str(db_path), read_only=True)
        try:
            audit_path = write_candidate_audit(conn, report_dir=out_dir)
        finally:
            conn.close()
        typer.echo(f"wrote {audit_path}")
    if html:
        from ai_codescan.html_report import render_html_report  # noqa: PLC0415

        conn = duckdb.connect(str(db_path), read_only=True) if db_path.is_file() else None
        try:
            html_path = render_html_report(
                verified_findings, out_dir=out_dir, conn=conn, target_name=repo_id
            )
        finally:
            if conn is not None:
                conn.close()
        typer.echo(f"wrote {html_path} (open in a browser)")
    if written == 0:
        typer.echo("no verified findings to report (run validate first or check gate-3)")


def _hitl_gate(label: str) -> None:
    """Pause the one-shot pipeline for human review.

    The preceding gate command (``gate-1`` / ``gate-2`` / ``gate-3``) has
    already opened the relevant file(s) in ``$EDITOR``; this just waits for
    the user to confirm they are done. Only called when HITL is enabled.
    A non-interactive stdin (piped input) is treated as "continue" so the
    runner does not hang.
    """
    typer.echo(f"[HITL] {label} — review the editor, then press Enter here to continue.")
    try:
        input()
    except EOFError:
        typer.echo("[HITL] stdin is not interactive; continuing.")


@app.command("scan")
def scan(  # noqa: PLR0913 - Typer command surface is intentionally explicit
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Target repo to scan.")] = Path("."),
    skip_hitl: Annotated[
        bool,
        typer.Option("--skip-hitl", help="Run fully unattended — no $EDITOR review pauses."),
    ] = False,
    llm_provider: Annotated[str, typer.Option("--llm-provider")] = "claude",
    llm_model: Annotated[str, typer.Option("--llm-model")] = "",
    engine: Annotated[
        str,
        typer.Option(
            "--engine",
            help="Static prep engine: hybrid (recommended), codeql, or llm-heavy.",
        ),
    ] = "hybrid",
    report_dir: Annotated[
        Path | None,
        typer.Option("--report-dir", help="Where to write the HTML report (default: ./report/)."),
    ] = None,
) -> None:
    """One-shot pipeline: prep -> nominate -> analyze -> validate -> HTML report.

    Runs every stage unattended. At each HITL gate the relevant file opens
    in ``$EDITOR`` for review; ``--skip-hitl`` runs fully unattended (every
    gate auto-accepts). The validator (PoC + Docker sandbox) runs but is
    non-fatal — a host without Docker still completes the scan, just with
    no findings flipped to verified.

    Scan trusted source only: the prep stage may execute target build tooling
    through SCIP and CodeQL outside a sandbox.
    """
    cache_root: Path = ctx.obj["cache_root"]
    llm_args = ["--llm-provider", llm_provider]
    if llm_model:
        llm_args += ["--llm-model", llm_model]
    out_dir = report_dir if report_dir is not None else Path.cwd() / "report"

    def _stage(name: str, *args: str, fatal: bool = True) -> bool:
        # Each stage reuses the existing subcommand verbatim — the one-shot
        # runner is pure orchestration, not a reimplementation. Subprocesses
        # inherit the TTY so $EDITOR pauses and prompts work.
        cmd = [
            sys.executable,
            "-m",
            "ai_codescan",
            "--cache-dir",
            str(cache_root),
            name,
            *args,
        ]
        typer.echo(f"[secscan] -> {name} {' '.join(args)}".rstrip())
        result = subprocess.run(cmd, check=False)  # noqa: S603 - argv-only, no shell
        if result.returncode == 0:
            return True
        msg = f"[secscan] stage '{name}' failed (exit {result.returncode})"
        if fatal:
            typer.echo(msg, err=True)
            raise typer.Exit(code=1)
        typer.echo(f"{msg} — non-fatal, continuing", err=True)
        return False

    _stage("prep", str(target), *llm_args, "--engine", engine)
    _stage("nominate", *llm_args)
    if skip_hitl:
        _stage("gate-1", "--yes")
    else:
        _stage("gate-1")  # opens nominations.md in $EDITOR
        _hitl_gate("nominations")
    _stage("analyze", *llm_args)
    if skip_hitl:
        _stage("gate-2", "--yes")
    else:
        _stage("gate-2")  # opens findings/ in $EDITOR
        _hitl_gate("findings")
    # Phase 17: run the storage_taint fixpoint so stored-XSS / stored-injection
    # synthetic flows land in the index before the validator picks findings up.
    # Non-fatal — a repo without SQL/cache patterns simply yields zero rounds.
    _stage("taint-schema", fatal=False)
    _stage("validate", *llm_args, fatal=False)
    if skip_hitl:
        _stage("gate-3", "--yes")
    else:
        _stage("gate-3")
        _hitl_gate("sign-off")
    _stage("report", "--html", "--report-dir", str(out_dir))
    typer.echo(f"[secscan] done — open {out_dir / 'report.html'}")


def secscan_main() -> None:
    """Console-script entry point: ``secscan <path>`` == ``ai-codescan scan <path>``."""
    app(args=["scan", *sys.argv[1:]], prog_name="secscan")


@app.command("taint-schema")
def taint_schema(  # noqa: PLR0911, PLR0913, PLR0912, PLR0915 - CLI orchestrator
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    show: Annotated[bool, typer.Option("--show")] = False,
    edit: Annotated[bool, typer.Option("--edit")] = False,
    run: Annotated[
        bool,
        typer.Option("--run", help="Run the storage-taint fixpoint over the cached index."),
    ] = False,
    resolve: Annotated[
        bool,
        typer.Option(
            "--resolve",
            help=(
                "Resolve dynamic cache/queue keys via the storage-taint-resolver "
                "skill; merges accepted suggestions into schema.taint.yml under "
                "an `llm_suggested:` block."
            ),
        ),
    ] = False,
    init: Annotated[
        bool,
        typer.Option(
            "--init",
            help=(
                "Seed schema.taint.yml from the bundled docs/schema.taint.yml.example "
                "if it doesn't exist yet. The example demonstrates the supported "
                "kinds (cache_key/queue_topic/sql_column/env_var) and shows "
                "cross-language storage_id patterns."
            ),
        ),
    ] = False,
    llm_provider: Annotated[str, typer.Option("--llm-provider")] = "",
    llm_model: Annotated[str, typer.Option("--llm-model")] = "",
) -> None:
    """Inspect or edit ``schema.taint.yml`` (Layer 5 storage-taint annotations)."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    repo_dir = cache_root / repo_id
    schema_path = repo_dir / "schema.taint.yml"

    if init:
        if schema_path.is_file():
            typer.echo(f"schema.taint.yml already exists at {schema_path}; not overwriting")
            return
        example_path = Path(__file__).resolve().parent.parent / "docs" / "schema.taint.yml.example"
        if not example_path.is_file():
            typer.echo(f"example file missing at {example_path}", err=True)
            raise typer.Exit(code=1)
        repo_dir.mkdir(parents=True, exist_ok=True)
        schema_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")
        typer.echo(f"seeded schema.taint.yml from {example_path}")
        return

    if resolve:
        db = repo_dir / "index.duckdb"
        if not db.is_file():
            typer.echo("No index. Run prep first.", err=True)
            raise typer.Exit(code=1)
        snapshot_root = repo_dir / "source"
        conn = duckdb.connect(str(db), read_only=True)
        try:
            calls = find_unresolved_dynamic_calls(conn, snapshot_root=snapshot_root)
        finally:
            conn.close()
        if not calls:
            typer.echo("no unresolved dynamic storage calls; schema unchanged")
            return

        state = load_or_create(
            repo_dir,
            engine="codeql",
            temperature=0.0,
            target_bug_classes=[],
            llm_provider=llm_provider or "claude",
            llm_model=llm_model or None,
        )
        write_resolver_queue(state.run_dir, calls)
        provider = LLMConfig(provider=state.llm_provider, model=state.llm_model)
        if not is_available(provider.provider):
            queue_path = state.run_dir / "storage_resolver" / "queue.jsonl"
            typer.echo(
                f"{provider.provider} CLI not on PATH; skipping skill loop. "
                f"Wrote {len(calls)} candidates to {queue_path} for manual triage."
            )
            return
        cmd_script = write_llm_cmd_script(state.run_dir / ".llm-cmd-resolver.sh", provider)
        skill_dir = Path(__file__).resolve().parent / "skills" / "storage_taint_resolver"
        env = os.environ.copy()
        env["AICS_RUN_DIR"] = str(state.run_dir)
        env["AICS_SKILL_DIR"] = str(skill_dir)
        env["AICS_LLM_CMD"] = str(cmd_script)
        from ai_codescan.review_cache import build_llm_context_fingerprint  # noqa: PLC0415

        env["AICS_LLM_CONTEXT"] = build_llm_context_fingerprint(
            provider,
            source_root=snapshot_root,
        )
        env["CLAUDE_NO_AUTO_REGISTER"] = "1"
        # Stage repo.md + schema.taint.yml as inputs.
        inputs_dir = state.run_dir / "inputs"
        inputs_dir.mkdir(parents=True, exist_ok=True)
        if (repo_dir / "repo.md").is_file():
            shutil.copyfile(repo_dir / "repo.md", inputs_dir / "repo.md")
        if schema_path.is_file():
            shutil.copyfile(schema_path, inputs_dir / "schema.taint.yml")
        subprocess.run(  # noqa: S603 - argv-only, no shell
            ["bash", str(skill_dir / "scripts" / "loop.sh")],  # noqa: S607
            env=env,
            check=True,
        )
        proposals = parse_resolver_proposals(state.run_dir)
        merged = merge_proposals_into_schema(schema_path, proposals)
        typer.echo(
            f"resolver: {len(calls)} candidates, {len(proposals)} proposals returned, "
            f"{merged} merged into schema.taint.yml under llm_suggested:"
        )
        return

    if run:
        db = repo_dir / "index.duckdb"
        if not db.is_file():
            typer.echo("No index. Run prep first.", err=True)
            raise typer.Exit(code=1)
        snapshot_root = repo_dir / "source"
        conn = duckdb.connect(str(db))
        try:
            stats = run_full_fixpoint(conn, snapshot_root=snapshot_root, schema_path=schema_path)
        finally:
            conn.close()
        typer.echo(
            f"fixpoint: rounds={stats['rounds_run']} new_flows={stats['new_flows']} "
            f"locations={stats['storage_locations']} "
            f"reads={stats['storage_reads']} derived={stats['storage_taint_derived']} "
            f"llm_seeded={stats.get('llm_seeded_locations', 0)}/"
            f"{stats.get('llm_seeded_reads', 0)}"
        )
        return

    if show:
        data = load_schema_yaml(schema_path)
        if not data:
            typer.echo("(empty schema.taint.yml — run `taint-schema --run` to seed it)")
        else:
            typer.echo(yaml.safe_dump(data, sort_keys=True))
        db = repo_dir / "index.duckdb"
        if db.is_file():
            conn = duckdb.connect(str(db), read_only=True)
            try:
                rows = conn.execute(
                    """
                    SELECT t.storage_id, t.derived_tid, t.confidence,
                           (SELECT COUNT(*) FROM storage_writes w
                            WHERE w.storage_id = t.storage_id) AS writes,
                           (SELECT COUNT(*) FROM storage_reads r
                            WHERE r.storage_id = t.storage_id) AS reads
                    FROM storage_taint t
                    ORDER BY t.storage_id
                    """
                ).fetchall()
            finally:
                conn.close()
            if rows:
                typer.echo("")
                typer.echo("dirty storage locations:")
                typer.echo(
                    _format_rows(
                        ["storage_id", "derived_tid", "confidence", "writes", "reads"],
                        rows,
                    )
                )
        return

    if edit:
        if not schema_path.is_file():
            save_schema_yaml(
                schema_path,
                {"tables": {}, "caches": {}, "queues": {}, "files": {}, "envs": {}},
            )
        editor = os.environ.get("EDITOR", "vi")
        subprocess.run(  # noqa: S603 - editor is user-controlled, no shell
            [editor, str(schema_path)],  # noqa: S607
            check=False,
        )
        return

    typer.echo("specify one of --show, --edit, or --run")
    raise typer.Exit(code=1)


@app.command()
def visualize(  # noqa: PLR0913 - flag plumbing matches user-visible CLI surface
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    out: Annotated[
        Path,
        typer.Option("--out", help="Output file path (extension or --fmt picks the format)."),
    ] = Path("flows.svg"),
    fmt: Annotated[
        str,
        typer.Option(
            "--fmt",
            help="Output format: dot, svg, or png.",
        ),
    ] = "svg",
    cwe: Annotated[str, typer.Option("--cwe", help="Filter to a single CWE.")] = "",
    limit: Annotated[int, typer.Option("--limit", help="Maximum flows to render.")] = 200,
) -> None:
    """Render flows as a Graphviz graph (svg / png / dot)."""
    if fmt not in {"dot", "svg", "png"}:
        typer.echo(f"--fmt {fmt} is not supported (choose dot, svg, or png).", err=True)
        raise typer.Exit(code=2)

    # Default ``--out flows.svg`` carries the wrong extension when the user
    # passes ``--fmt dot`` (or ``png``) without overriding ``--out``. If
    # ``out`` is the default and ``fmt`` differs from the default's suffix,
    # rewrite the extension so the filename matches the content.
    if out == Path("flows.svg") and fmt != "svg":
        out = out.with_suffix(f".{fmt}")

    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    db = cache_root / repo_id / "index.duckdb"
    if not db.is_file():
        typer.echo("No index. Run prep first.", err=True)
        raise typer.Exit(code=1)
    conn = duckdb.connect(str(db), read_only=True)
    try:
        target = render_graph(
            conn,
            out_path=out,
            fmt=_cast(OutputFormat, fmt),
            cwe=cwe or None,
            limit=limit,
        )
    finally:
        conn.close()
    typer.echo(f"wrote {target}")


def _protected_skills_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "ai-codescan" / "protected_skills.txt"


def _read_protected() -> set[str]:
    path = _protected_skills_path()
    if not path.is_file():
        return set()
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def _write_protected(names: set[str]) -> None:
    path = _protected_skills_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_names = sorted(names)
    body = "# Skills protected from `install-skills` overwrite. One name per line.\n" + "\n".join(
        sorted_names
    )
    path.write_text(body + "\n", encoding="utf-8")


@app.command("install-skills")
def install_skills(
    protect: Annotated[
        list[str],
        typer.Option(
            "--protect",
            help="Mark a skill as protected; never overwritten by future install-skills.",
        ),
    ] = [],  # noqa: B006 - typer requires a literal default
    unprotect: Annotated[
        list[str],
        typer.Option(
            "--unprotect",
            help="Remove a skill from the protected list.",
        ),
    ] = [],  # noqa: B006 - typer requires a literal default
    list_protected: Annotated[
        bool,
        typer.Option("--list-protected", help="Print the current protected list and exit."),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite even protected skills."),
    ] = False,
) -> None:
    """Copy bundled skills into ~/.claude/skills/, honouring the protected list."""
    protected = _read_protected()
    if protect:
        protected.update(protect)
        _write_protected(protected)
        typer.echo(f"protected: {', '.join(sorted(protect))}")
    if unprotect:
        protected.difference_update(unprotect)
        _write_protected(protected)
        typer.echo(f"unprotected: {', '.join(sorted(unprotect))}")
    if list_protected:
        if protected:
            for name in sorted(protected):
                typer.echo(name)
        else:
            typer.echo("(no protected skills)")
        return

    skill_root = Path(__file__).resolve().parent / "skills"
    dest_root = Path.home() / ".claude" / "skills"
    dest_root.mkdir(parents=True, exist_ok=True)
    installed: list[Path] = []
    skipped: list[str] = []
    for src in skill_root.iterdir() if skill_root.is_dir() else []:
        if not src.is_dir():
            continue
        dest = dest_root / src.name
        if dest.exists() and src.name in protected and not force:
            skipped.append(src.name)
            continue
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        installed.append(dest)
    for d in installed:
        typer.echo(f"installed skill to {d}")
    for name in skipped:
        typer.echo(f"skipped {name} (protected; use --force to overwrite)")


@app.command()
def serve(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    host: Annotated[str, typer.Option("--host", help="Bind host.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port.")] = 8765,
    open_browser: Annotated[
        bool, typer.Option("--open/--no-open", help="Open browser after start.")
    ] = True,
) -> None:
    """Serve the React Flow viewer for a cached repo's flows + notes."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    db_path = cache_root / repo_id / "index.duckdb"
    if not db_path.is_file():
        typer.echo("No prep output. Run `ai-codescan prep` first.", err=True)
        raise typer.Exit(code=1)
    server = start_server(db_path, host=host, port=port)
    addr = server.server_address
    bound_host, bound_port = str(addr[0]), int(addr[1])
    url = f"http://{bound_host}:{bound_port}"
    typer.echo(f"viewer at {url}  (Ctrl-C to stop)")
    if open_browser:
        with contextlib.suppress(Exception):
            webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        typer.echo("\nshutting down")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    app()
