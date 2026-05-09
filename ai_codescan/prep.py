"""End-to-end ``prep`` orchestration."""

from __future__ import annotations

import logging
from pathlib import Path

import duckdb

from ai_codescan.ast.runner import AstJob, run_jobs
from ai_codescan.config import compute_repo_id
from ai_codescan.engines.codeql import build_database, run_queries
from ai_codescan.entrypoints.detectors import Entrypoint, detect_entrypoints
from ai_codescan.entrypoints.ingest import ingest_entrypoints
from ai_codescan.entrypoints.render import render_entrypoints_md
from ai_codescan.index.duckdb_ingest import ingest as duckdb_ingest
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.index.scip import build_scip_index
from ai_codescan.ingest.sarif import ingest_sarif
from ai_codescan.repo_md import render_repo_md
from ai_codescan.sidecars import emit_sidecars
from ai_codescan.snapshot import SnapshotResult, take_snapshot
from ai_codescan.stack_detect import Project, ProjectKind, detect_projects
from ai_codescan.taxonomy.loader import BugClass

log = logging.getLogger(__name__)

_SCIP_RANGE_WITH_END_LINE = 3
"""SCIP occurrence range with [start_line, start_col, end_col] is len 3; with end_line is len 4."""


_PYTHON_SKIP_PARTS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "site-packages",
    }
)


def _files_for_project(
    snapshot_root: Path, project: Project
) -> tuple[list[Path], list[Path], list[Path]]:
    """Return (ts_files, html_files, python_files) under ``project.base_path``."""
    base = snapshot_root / project.base_path
    ts = [
        p
        for p in base.rglob("*")
        if p.is_file()
        and p.suffix in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
        and "node_modules" not in p.parts
    ]
    html = [
        p
        for p in base.rglob("*")
        if p.is_file() and p.suffix in {".html", ".htm"} and "node_modules" not in p.parts
    ]
    python = [
        p
        for p in base.rglob("*")
        if p.is_file()
        and p.suffix in {".py", ".pyi"}
        and not any(part in _PYTHON_SKIP_PARTS for part in p.parts)
    ]
    return ts, html, python


def _ast_jobs_for_project(snapshot_root: Path, project: Project) -> list[AstJob]:
    base = snapshot_root / project.base_path
    ts_files, html_files, py_files = _files_for_project(snapshot_root, project)
    jobs: list[AstJob] = []
    if ts_files:
        tsconfig = base / "tsconfig.json"
        jobs.append(
            AstJob(
                kind="ts",
                project_root=base,
                files=ts_files,
                tsconfig=tsconfig if tsconfig.is_file() else None,
            )
        )
    if html_files:
        jobs.append(AstJob(kind="html", project_root=base, files=html_files))
    if py_files and project.kind is ProjectKind.PYTHON:
        jobs.append(AstJob(kind="python", project_root=base, files=py_files))
    return jobs


def _scip_language_for_project(project: Project) -> str | None:
    """Return the SCIP indexer language for ``project``, or None to skip."""
    if project.kind is ProjectKind.NODE and "typescript" in project.languages:
        return "javascript"
    if project.kind is ProjectKind.PYTHON and "python" in project.languages:
        return "python"
    return None


def _build_scip_lookup(snapshot_root: Path, projects: list[Project], cache_dir: Path) -> dict:
    lookup: dict = {}
    for project in projects:
        scip_language = _scip_language_for_project(project)
        if scip_language is None:
            continue
        try:
            result = build_scip_index(
                snapshot_root / project.base_path,
                cache_dir=cache_dir,
                project_id=f"{project.name}-{project.base_path.as_posix().replace('/', '_')}",
                language=scip_language,
            )
        except (RuntimeError, OSError) as exc:
            log.warning("scip index failed for %s: %s", project.name, exc)
            continue
        for doc in result.iter_documents():
            file = (snapshot_root / project.base_path / doc.relative_path).as_posix()
            for occ in doc.occurrences:
                start = occ.range[0] + 1
                end = occ.range[2] + 1 if len(occ.range) >= _SCIP_RANGE_WITH_END_LINE else start
                if occ.symbol:
                    lookup[(file, start, end)] = f"scip:{occ.symbol}"
    return lookup


def _codeql_language_for_project(project: Project) -> str | None:
    """Return the CodeQL language token for ``project``, or None if unsupported."""
    if project.kind is ProjectKind.NODE and project.languages.intersection(
        {"javascript", "typescript"}
    ):
        return "javascript"
    if project.kind is ProjectKind.PYTHON and "python" in project.languages:
        return "python"
    return None


def _run_codeql_for_projects(
    snapshot_root: Path,
    projects: list[Project],
    repo_dir: Path,
    bug_classes: list[BugClass] | None,
    conn,
) -> None:
    tags: list[str] = []
    if bug_classes:
        for c in bug_classes:
            tags.extend(c.codeql_tags)
    for project in projects:
        language = _codeql_language_for_project(project)
        if language is None:
            continue
        project_id = f"{project.name}-{project.base_path.as_posix().replace('/', '_')}"
        try:
            db_path = build_database(
                snapshot_root / project.base_path,
                cache_dir=repo_dir,
                project_id=project_id,
                language=language,
            )
            result = run_queries(
                db_path,
                cache_dir=repo_dir,
                project_id=project_id,
                codeql_tags=tags,
                language=language,
            )
            ingest_sarif(
                conn,
                sarif_path=result.sarif_path,
                project_id=project_id,
                snapshot_root=snapshot_root,
                engine="codeql",
            )
        except (RuntimeError, OSError) as exc:
            log.warning("codeql failed for %s: %s", project.name, exc)


def run_prep(  # noqa: PLR0913 - keyword-only orchestration knobs
    target: Path,
    *,
    cache_root: Path,
    commit: str | None = None,
    bug_classes: list[BugClass] | None = None,
    engine: str = "codeql",
    quiet: bool = False,
    force: bool = False,
) -> tuple[SnapshotResult, Path]:
    """Snapshot, detect, AST, SCIP, ingest. Returns the snapshot result and the duckdb path.

    When the snapshot is reused (manifest matched) and the DuckDB index already exists,
    the AST / SCIP / CodeQL stages are short-circuited and only cheap projections
    (sidecars + entrypoints.md) are re-emitted. Pass ``force=True`` to bypass.
    """
    repo_dir = cache_root / compute_repo_id(target)
    snap = take_snapshot(target, cache_dir=repo_dir, commit=commit)

    projects = detect_projects(snap.snapshot_dir)
    repo_md_path = repo_dir / "repo.md"
    repo_md_path.write_text(
        render_repo_md(target_name=target.name, projects=projects),
        encoding="utf-8",
    )

    db_path = repo_dir / "index.duckdb"
    incremental = (not force) and snap.skipped and db_path.is_file()

    conn = duckdb.connect(str(db_path))
    apply_schema(conn)

    if incremental:
        if not quiet:
            log.info("skipping AST/SCIP/CodeQL stages — cached results reused")
    else:
        scip_lookup = _build_scip_lookup(snap.snapshot_dir, projects, repo_dir)

        for project in projects:
            jobs = _ast_jobs_for_project(snap.snapshot_dir, project)
            if not jobs:
                continue
            files: list[dict] = []
            symbols: list[dict] = []
            xrefs: list[dict] = []
            for record in run_jobs(jobs):
                t = record["type"]
                if t == "file":
                    files.append(record)
                elif t == "symbol":
                    symbols.append(record)
                elif t == "xref":
                    xrefs.append(record)
            duckdb_ingest(
                conn,
                files=files,
                symbols=symbols,
                xrefs=xrefs,
                scip_lookup=scip_lookup,
                project_id=project.name,
                snapshot_root=snap.snapshot_dir,
            )
            entries = detect_entrypoints(xrefs=xrefs, symbols=symbols)
            ingest_entrypoints(conn, entries)

        if engine == "codeql":
            _run_codeql_for_projects(snap.snapshot_dir, projects, repo_dir, bug_classes, conn)

    all_entries_rows = conn.execute(
        "SELECT symbol_id, kind, signature, file, line FROM entrypoints"
    ).fetchall()
    all_entries: list[Entrypoint] = []
    for sym_id, kind, sig, file, line in all_entries_rows:
        all_entries.append(
            Entrypoint(
                symbol_id=sym_id,
                kind=kind,
                signature=sig,
                file=file or "",
                line=int(line or 0),
            )
        )
    (repo_dir / "entrypoints.md").write_text(
        render_entrypoints_md(target_name=target.name, entrypoints=all_entries),
        encoding="utf-8",
    )

    emit_sidecars(conn, snapshot_root=snap.snapshot_dir, sidecars_root=repo_dir / "sidecars")

    conn.close()
    return snap, db_path
