"""Command-line entry point for ai-codescan."""

from __future__ import annotations

import contextlib
import datetime as _dt
import shutil
import stat as stat_mod
from pathlib import Path
from typing import Annotated, Any

import duckdb
import typer

from ai_codescan.config import default_cache_root
from ai_codescan.prep import run_prep
from ai_codescan.taxonomy.loader import (
    UnknownBugClassError,
    list_classes,
    resolve_classes,
)

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


if __name__ == "__main__":
    app()
