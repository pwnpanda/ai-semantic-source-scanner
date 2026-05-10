"""Command-line entry point for ai-codescan."""

from __future__ import annotations

import contextlib
import datetime as _dt
import os
import shutil
import stat as stat_mod
import subprocess
import webbrowser
from pathlib import Path
from typing import Annotated, Any
from typing import cast as _cast

import duckdb
import typer
import yaml

from ai_codescan.analyzer import run_analyzer
from ai_codescan.config import compute_repo_id, default_cache_root
from ai_codescan.engines.codeql import run_queries
from ai_codescan.engines.hybrid import run_hybrid
from ai_codescan.engines.llm_heavy import run_llm_heavy_engine
from ai_codescan.findings.model import parse_finding
from ai_codescan.gate import apply_yes_to_all, selected_extensions
from ai_codescan.ingest.sarif import ingest_sarif
from ai_codescan.llm import LLMConfig, UnknownProviderError, is_available
from ai_codescan.nominator import run_nominator, write_llm_cmd_script
from ai_codescan.prep import run_prep
from ai_codescan.report import write_report
from ai_codescan.runs.state import load_or_create
from ai_codescan.server import serve as start_server
from ai_codescan.stack_detect import ProjectKind, detect_projects
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
            help="Static engine to run (Phase 1: only 'codeql' is supported).",
        ),
    ] = "codeql",
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
    """Snapshot, detect, AST, SCIP, then run the chosen engine(s) and ingest into DuckDB."""
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

    cache_root: Path = ctx.obj["cache_root"]
    quiet: bool = ctx.obj["quiet"]
    repo_dir_pre = cache_root / compute_repo_id(target)
    db_existed_before = (repo_dir_pre / "index.duckdb").is_file()
    snap, db_path = run_prep(
        target,
        cache_root=cache_root,
        commit=commit,
        bug_classes=bug_classes,
        # CodeQL prep stage runs when engine ∈ {codeql, hybrid}.
        engine="codeql" if engine in {"codeql", "hybrid"} else "none",
        quiet=quiet,
        force=force,
    )
    incremental_used = (not force) and snap.skipped and db_existed_before
    if incremental_used and not quiet:
        typer.echo("incremental: skipping AST/SCIP/CodeQL stages — cached results reused")
    if engine == "llm-heavy":
        repo_dir = cache_root / compute_repo_id(target)
        state = load_or_create(
            repo_dir,
            engine="llm-heavy",
            temperature=0.0,
            target_bug_classes=[c.name for c in bug_classes],
        )
        n = run_llm_heavy_engine(
            state,
            repo_dir=repo_dir,
            db_path=db_path,
            target_bug_classes=[c.name for c in bug_classes],
        )
        if not quiet:
            typer.echo(f"llm-heavy ingested {n} flow(s)")
    elif engine == "hybrid":
        # Walk detected projects and run Semgrep (+ Joern when on PATH), then dedupe.
        repo_dir = cache_root / compute_repo_id(target)
        snapshot_root = snap.snapshot_dir
        roots: list[tuple[Path, str, str]] = []
        for project in detect_projects(snapshot_root):
            if project.kind is ProjectKind.NODE:
                language = "javascript"
            elif project.kind is ProjectKind.PYTHON:
                language = "python"
            elif project.kind is ProjectKind.JAVA:
                language = "java"
            elif project.kind is ProjectKind.GO:
                language = "go"
            elif project.kind is ProjectKind.RUBY:
                language = "ruby"
            elif project.kind is ProjectKind.PHP:
                language = "php"
            else:
                continue
            project_id = f"{project.name}-{project.base_path.as_posix().replace('/', '_')}"
            roots.append((snapshot_root / project.base_path, project_id, language))
        stats = run_hybrid(
            roots,
            snapshot_root=snapshot_root,
            repo_dir=repo_dir,
            db_path=db_path,
        )
        if not quiet:
            typer.echo(
                f"hybrid: codeql={stats.codeql_flows} semgrep={stats.semgrep_flows} "
                f"joern={stats.joern_flows} deduped={stats.deduped}"
            )

    if not quiet:
        status_word = "skipped" if snap.skipped else "took"
        commit_label = f" @ {snap.commit_sha[:8]}" if snap.commit_sha else ""
        typer.echo(f"snapshot {status_word} ({snap.method}){commit_label}")
        typer.echo(f"index at {db_path}")
        typer.echo(f"bug classes: {', '.join(c.name for c in bug_classes)}")
        typer.echo(f"engine: {engine}")

        # Periodic taxonomy stale-check (cheap; weekly cadence by default).
        check = maybe_run_periodic_check()
        if check is not None and check.missing_tags:
            typer.echo(
                f"note: taxonomy may be stale — {len(check.missing_tags)} CodeQL "
                "tag(s) not in bug_classes.yaml. Run `ai-codescan taxonomy diff`."
            )


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

    if symbol:
        row = conn.execute("SELECT file FROM symbols WHERE id = ?", [symbol]).fetchone()
        if not row:
            typer.echo(f"unknown symbol id: {symbol}", err=True)
            raise typer.Exit(code=1)
        file = row[0]

    typer.echo(render_file_view(conn, file=file))


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

    def _force(_func, path, _exc):
        Path(path).chmod(stat_mod.S_IWUSR | stat_mod.S_IRUSR | stat_mod.S_IXUSR)
        Path(path).unlink(missing_ok=True)

    shutil.rmtree(repo_dir, onexc=_force)
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
    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=temperature,
        target_bug_classes=[c.name for c in bug_classes],
        llm_provider=llm.provider,
        llm_model=llm.model,
    )
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
    yes: Annotated[bool, typer.Option("--yes")] = False,
    commit: _CommitOption = None,
    llm_provider: Annotated[str, typer.Option("--llm-provider")] = "claude",
    llm_model: Annotated[str, typer.Option("--llm-model")] = "",
) -> None:
    """End-to-end Phase 1: prep + nominate + gate-1 in one shot."""
    flags: list[str] = []
    if target_bug_class:
        flags += ["--target-bug-class", target_bug_class]
    if commit:
        flags += ["--commit", commit]

    cache_root: Path = ctx.obj["cache_root"]
    cache_arg = ["--cache-dir", str(cache_root)]
    rc = subprocess.call(  # noqa: S603 - argv-only, no shell
        ["ai-codescan", *cache_arg, "prep", str(target), *flags],  # noqa: S607
    )
    if rc != 0:
        raise typer.Exit(code=rc)

    repo_id = compute_repo_id(target)
    nominate_args = [
        "--repo-id",
        repo_id,
        "--temperature",
        str(temperature),
        "--llm-provider",
        llm_provider,
    ]
    if llm_model:
        nominate_args += ["--llm-model", llm_model]
    if target_bug_class:
        nominate_args += ["--target-bug-class", target_bug_class]
    rc = subprocess.call(  # noqa: S603 - argv-only, no shell
        ["ai-codescan", *cache_arg, "nominate", *nominate_args],  # noqa: S607
    )
    if rc != 0:
        raise typer.Exit(code=rc)

    gate_args = ["--repo-id", repo_id]
    if yes:
        gate_args.append("--yes")
    subprocess.call(  # noqa: S603 - argv-only, no shell
        ["ai-codescan", *cache_arg, "gate-1", *gate_args],  # noqa: S607
    )


@app.command()
def analyze(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    llm_provider: Annotated[str, typer.Option("--llm-provider")] = "claude",
    llm_model: Annotated[str, typer.Option("--llm-model")] = "",
    temperature: Annotated[float, typer.Option("--temperature")] = 0.0,
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
    queue = run_analyzer(state, repo_dir=repo_dir, db_path=db_path, llm=llm)
    typer.echo(f"queue at {queue}")


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
def report(
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
    for fp in sorted(findings_dir.glob("*.md")):
        f = parse_finding(fp.read_text(encoding="utf-8"))
        if f.status != "verified":
            continue
        target = write_report(f, report_dir=out_dir)
        typer.echo(f"wrote {target}")
        written += 1
    if written == 0:
        typer.echo("no verified findings to report (run validate first or check gate-3)")


@app.command("taint-schema")
def taint_schema(  # noqa: PLR0913, PLR0912, PLR0915 - CLI orchestrator
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
    llm_provider: Annotated[str, typer.Option("--llm-provider")] = "",
    llm_model: Annotated[str, typer.Option("--llm-model")] = "",
) -> None:
    """Inspect or edit ``schema.taint.yml`` (Layer 5 storage-taint annotations)."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    repo_dir = cache_root / repo_id
    schema_path = repo_dir / "schema.taint.yml"

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
            check=False,
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
