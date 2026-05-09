"""Command-line entry point for ai-codescan."""

from __future__ import annotations

import contextlib
import datetime as _dt
import os
import shutil
import stat as stat_mod
import subprocess
from pathlib import Path
from typing import Annotated, Any

import duckdb
import typer

from ai_codescan.analyzer import run_analyzer
from ai_codescan.config import compute_repo_id, default_cache_root
from ai_codescan.engines.codeql import run_queries
from ai_codescan.findings.model import parse_finding
from ai_codescan.gate import apply_yes_to_all, selected_extensions
from ai_codescan.ingest.sarif import ingest_sarif
from ai_codescan.llm import LLMConfig, UnknownProviderError
from ai_codescan.nominator import run_nominator
from ai_codescan.prep import run_prep
from ai_codescan.runs.state import load_or_create
from ai_codescan.taxonomy.loader import (
    UnknownBugClassError,
    list_classes,
    resolve_classes,
)
from ai_codescan.validator import run_validator
from ai_codescan.views import render_file_view

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
def prep(
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
) -> None:
    """Snapshot, detect, AST, SCIP, CodeQL, ingest into DuckDB."""
    if engine != "codeql":
        typer.echo(f"--engine {engine} is not supported in Phase 1.", err=True)
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
    snap, db_path = run_prep(
        target,
        cache_root=cache_root,
        commit=commit,
        bug_classes=bug_classes,
        engine=engine,
    )
    if not quiet:
        status_word = "skipped" if snap.skipped else "took"
        commit_label = f" @ {snap.commit_sha[:8]}" if snap.commit_sha else ""
        typer.echo(f"snapshot {status_word} ({snap.method}){commit_label}")
        typer.echo(f"index at {db_path}")
        typer.echo(f"bug classes: {', '.join(c.name for c in bug_classes)}")


@app.command("list-bug-classes")
def list_bug_classes() -> None:
    """Print every taxonomy entry."""
    rows = sorted(list_classes(), key=lambda c: c.name)
    for c in rows:
        aliases = f" ({', '.join(c.aliases)})" if c.aliases else ""
        cwes = ", ".join(c.cwes)
        typer.echo(f"{c.name}{aliases}\t{c.group}\t{cwes}")


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


@app.command("install-skills")
def install_skills() -> None:
    """Copy bundled skills into ~/.claude/skills/."""
    skill_root = Path(__file__).resolve().parent / "skills"
    dest_root = Path.home() / ".claude" / "skills"
    dest_root.mkdir(parents=True, exist_ok=True)
    installed: list[Path] = []
    for src in (skill_root.iterdir() if skill_root.is_dir() else []):
        if not src.is_dir():
            continue
        dest = dest_root / src.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        installed.append(dest)
    for d in installed:
        typer.echo(f"installed skill to {d}")


if __name__ == "__main__":
    app()
