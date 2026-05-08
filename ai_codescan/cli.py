"""Command-line entry point for ai-codescan."""

from __future__ import annotations

import shutil
import stat as stat_mod
from pathlib import Path
from typing import Annotated

import typer

from ai_codescan.config import default_cache_root

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
) -> None:
    """Snapshot ``target``, detect its stack, and write ``repo.md``."""
    typer.echo("prep is not implemented yet (Task 10)")
    raise typer.Exit(code=1)


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


@cache_app.command("list")
def cache_list(ctx: typer.Context) -> None:
    """List cached repos."""
    cache_root: Path = ctx.obj["cache_root"]
    if not cache_root.exists():
        typer.echo("No cached repos.")
        return
    repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
    if not repos:
        typer.echo("No cached repos.")
        return
    for name in repos:
        typer.echo(name)


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
