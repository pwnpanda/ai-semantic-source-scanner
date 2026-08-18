"""End-to-end ``prep`` orchestration."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from contextlib import suppress
from dataclasses import replace
from pathlib import Path

import duckdb

from ai_codescan.artifact_id import project_artifact_id
from ai_codescan.ast.runner import AstJob, run_jobs
from ai_codescan.cache_state import build_scan_fingerprint, scan_stage_is_current, set_scan_stage
from ai_codescan.codeql_extensions import render_codeql_yaml_extensions
from ai_codescan.config import compute_repo_id
from ai_codescan.engines.codeql import build_database, run_queries
from ai_codescan.entrypoints.detectors import Entrypoint, detect_entrypoints
from ai_codescan.entrypoints.ingest import ingest_entrypoints
from ai_codescan.entrypoints.render import render_entrypoints_md
from ai_codescan.index.duckdb_ingest import ingest as duckdb_ingest
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.index.scip import build_scip_index
from ai_codescan.ingest.sarif import ingest_sarif
from ai_codescan.manifest import IGNORED_SOURCE_DIRS
from ai_codescan.repo_lock import repo_scan_lock
from ai_codescan.repo_md import render_repo_md
from ai_codescan.sidecars import emit_sidecars
from ai_codescan.snapshot import SnapshotResult, take_snapshot
from ai_codescan.stack_detect import Project, ProjectKind, detect_projects
from ai_codescan.taxonomy.loader import BugClass
from ai_codescan.third_party import scip_pb2

log = logging.getLogger(__name__)

_SCIP_SINGLE_LINE_RANGE_LENGTH = 3
_SCIP_MULTI_LINE_RANGE_LENGTH = 4

_PYTHON_SKIP_PARTS = IGNORED_SOURCE_DIRS | {"env"}

_JAVA_SKIP_PARTS = IGNORED_SOURCE_DIRS

_GO_SKIP_PARTS = IGNORED_SOURCE_DIRS

_RUBY_SKIP_PARTS = IGNORED_SOURCE_DIRS | {"tmp", "log"}

_PHP_SKIP_PARTS = IGNORED_SOURCE_DIRS | {
    "storage",  # Laravel storage/
}
_PHP_SKIP_SUBPATHS = frozenset({("wp-content", "uploads"), ("wp-content", "cache")})

_CSHARP_SKIP_PARTS = IGNORED_SOURCE_DIRS | {
    "bin",  # .NET build output
    "obj",  # .NET intermediate output
    ".vs",
}

_CONFIG_SKIP_PARTS = IGNORED_SOURCE_DIRS

_SOURCE_INDEX_TABLES = (
    "storage_taint",
    "storage_reads",
    "storage_writes",
    "storage_locations",
    "flow_metadata",
    "flows",
    "taint_sources",
    "taint_sinks",
    "entrypoints",
    "xrefs",
    "symbols",
    "files",
    "candidate_scores",
)

_PREP_INCOMPLETE_MARKER = ".prep-incomplete"


def _has_skipped_part(path: Path, *, base: Path, skipped: frozenset[str]) -> bool:
    return any(part in skipped for part in path.relative_to(base).parts)


def _has_skipped_subpath(
    path: Path,
    *,
    base: Path,
    skipped: frozenset[tuple[str, ...]],
) -> bool:
    parts = path.relative_to(base).parts
    return any(
        tuple(parts[index : index + len(candidate)]) == candidate
        for candidate in skipped
        for index in range(len(parts) - len(candidate) + 1)
    )


def _source_files(
    base: Path,
    *,
    suffixes: set[str],
    skipped: frozenset[str],
) -> list[Path]:
    return [
        path
        for path in base.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.suffix in suffixes
        and not _has_skipped_part(path, base=base, skipped=skipped)
    ]


def _clear_source_index(conn: duckdb.DuckDBPyConnection) -> None:
    """Clear derived source state before rebuilding a changed snapshot."""
    for table in _SOURCE_INDEX_TABLES:
        conn.execute(f"DELETE FROM {table}")  # noqa: S608 - names are a fixed internal tuple


def _files_for_project(
    snapshot_root: Path, project: Project
) -> tuple[
    list[Path],
    list[Path],
    list[Path],
    list[Path],
    list[Path],
    list[Path],
    list[Path],
    list[Path],
    list[Path],
    list[Path],
    list[Path],
]:
    """Return per-language file lists under ``project.base_path``.

    Order: ``(ts, html, python, java, go, ruby, php, csharp, kotlin, bash, yaml)``.
    Kotlin shares JVM tooling with Java, so a JAVA-kind project that also
    contains ``.kt`` / ``.kts`` files emits both a ``java`` and a
    ``kotlin`` AST job. Bash scripts emit their own AST job whenever the
    project carries ``.sh`` / ``.bash`` files (CI / glue scripts in
    polyglot repos count too). YAML files emit a ``yaml`` AST job in every
    project so application and deployment configuration stays visible beside
    the primary source language.
    """
    base = snapshot_root / project.base_path
    ts = _source_files(
        base,
        suffixes={".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"},
        skipped=IGNORED_SOURCE_DIRS,
    )
    html = _source_files(base, suffixes={".html", ".htm"}, skipped=_CONFIG_SKIP_PARTS)
    python = _source_files(base, suffixes={".py", ".pyi"}, skipped=_PYTHON_SKIP_PARTS)
    java = _source_files(base, suffixes={".java"}, skipped=_JAVA_SKIP_PARTS)
    kotlin = _source_files(base, suffixes={".kt", ".kts"}, skipped=_JAVA_SKIP_PARTS)
    go = _source_files(base, suffixes={".go"}, skipped=_GO_SKIP_PARTS)
    ruby = _source_files(base, suffixes={".rb", ".rake"}, skipped=_RUBY_SKIP_PARTS)
    php = [
        path
        for path in _source_files(base, suffixes={".php", ".phtml"}, skipped=_PHP_SKIP_PARTS)
        if not _has_skipped_subpath(path, base=base, skipped=_PHP_SKIP_SUBPATHS)
    ]
    csharp = _source_files(base, suffixes={".cs"}, skipped=_CSHARP_SKIP_PARTS)
    bash = _source_files(base, suffixes={".sh", ".bash"}, skipped=IGNORED_SOURCE_DIRS)
    yaml_files = _source_files(base, suffixes={".yml", ".yaml"}, skipped=_CONFIG_SKIP_PARTS)
    return ts, html, python, java, go, ruby, php, csharp, kotlin, bash, yaml_files


def _ast_jobs_for_project(snapshot_root: Path, project: Project) -> list[AstJob]:
    base = snapshot_root / project.base_path
    (
        ts_files,
        html_files,
        py_files,
        java_files,
        go_files,
        ruby_files,
        php_files,
        csharp_files,
        kotlin_files,
        bash_files,
        yaml_files,
    ) = _files_for_project(snapshot_root, project)
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
    if java_files and project.kind is ProjectKind.JAVA:
        jobs.append(AstJob(kind="java", project_root=base, files=java_files))
    if go_files and project.kind is ProjectKind.GO:
        jobs.append(AstJob(kind="go", project_root=base, files=go_files))
    if ruby_files and project.kind is ProjectKind.RUBY:
        jobs.append(AstJob(kind="ruby", project_root=base, files=ruby_files))
    if php_files and project.kind is ProjectKind.PHP:
        jobs.append(AstJob(kind="php", project_root=base, files=php_files))
    if csharp_files and project.kind is ProjectKind.CSHARP:
        jobs.append(AstJob(kind="csharp", project_root=base, files=csharp_files))
    # Kotlin files inside a JVM project share the project's manifest and
    # CodeQL extractor; emit a ``kotlin`` AST job so .kt / .kts symbols
    # land in the index alongside any .java siblings.
    if kotlin_files and project.kind is ProjectKind.JAVA:
        jobs.append(AstJob(kind="kotlin", project_root=base, files=kotlin_files))
    # Bash scripts: emit a ``bash`` AST job for any project that contains
    # them — glue scripts in polyglot repos (e.g. CI helpers in a Node
    # repo) also benefit from xrefs and symbol indexing. Bare-source
    # detection covers BASH-kind projects on its own.
    if bash_files:
        jobs.append(AstJob(kind="bash", project_root=base, files=bash_files))
    # Configuration remains part of the attack surface in polyglot repos.
    # In particular, application.yml and deployment manifests can contain
    # credentials and insecure framework settings that are invisible if YAML
    # is indexed only when it is the repository's primary project kind.
    if yaml_files:
        jobs.append(AstJob(kind="yaml", project_root=base, files=yaml_files))
    return jobs


def _deduplicate_ast_jobs(
    jobs: list[AstJob],
    indexed_files: set[tuple[str, Path]],
) -> list[AstJob]:
    """Keep each language/file pair in only one project job."""
    unique_jobs: list[AstJob] = []
    for job in jobs:
        unique_files = [path for path in job.files if (job.kind, path) not in indexed_files]
        indexed_files.update((job.kind, path) for path in unique_files)
        if unique_files:
            unique_jobs.append(
                AstJob(
                    kind=job.kind,
                    project_root=job.project_root,
                    files=unique_files,
                    tsconfig=job.tsconfig,
                )
            )
    return unique_jobs


def _scip_language_for_project(project: Project) -> str | None:
    """Return the SCIP indexer language for ``project``, or None to skip."""
    if project.kind is ProjectKind.NODE and "typescript" in project.languages:
        return "javascript"
    if project.kind is ProjectKind.PYTHON and "python" in project.languages:
        return "python"
    if project.kind is ProjectKind.JAVA and (
        "java" in project.languages or "kotlin" in project.languages
    ):
        return "java"
    if project.kind is ProjectKind.GO and "go" in project.languages:
        return "go"
    return None


def _scip_occurrence_line_range(
    occurrence: scip_pb2.Occurrence,
) -> tuple[int, int] | None:
    typed_range = occurrence.WhichOneof("typed_range")
    if typed_range == "single_line_range":
        line = occurrence.single_line_range.line + 1
        return line, line
    if typed_range == "multi_line_range":
        return (
            occurrence.multi_line_range.start_line + 1,
            occurrence.multi_line_range.end_line + 1,
        )

    legacy_range = occurrence.range
    if len(legacy_range) == _SCIP_SINGLE_LINE_RANGE_LENGTH:
        line = legacy_range[0] + 1
        return line, line
    if len(legacy_range) == _SCIP_MULTI_LINE_RANGE_LENGTH:
        return legacy_range[0] + 1, legacy_range[2] + 1
    return None


def _scip_tool_is_available(language: str) -> bool:
    if language == "java" and os.environ.get("AI_CODESCAN_SCIP_JAVA_INDEX"):
        return True
    tool = {
        "javascript": "scip-typescript",
        "python": "scip-python",
        "java": "scip-java",
        "go": "scip-go",
    }[language]
    return shutil.which(tool) is not None


def _build_scip_lookup(
    snapshot_root: Path,
    projects: list[Project],
    cache_dir: Path,
) -> tuple[dict, bool]:
    lookup: dict = {}
    had_failures = False
    for project in projects:
        scip_language = _scip_language_for_project(project)
        if scip_language is None:
            continue
        if not _scip_tool_is_available(scip_language):
            log.warning("scip index unavailable for %s (%s)", project.name, scip_language)
            continue
        try:
            result = build_scip_index(
                snapshot_root / project.base_path,
                cache_dir=cache_dir,
                project_id=project_artifact_id(project.name, project.base_path),
                language=scip_language,
            )
        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
            log.warning("scip index failed for %s: %s", project.name, exc)
            had_failures = True
            continue
        for doc in result.iter_documents():
            file = (snapshot_root / project.base_path / doc.relative_path).as_posix()
            for occ in doc.occurrences:
                line_range = _scip_occurrence_line_range(occ)
                if not occ.symbol or line_range is None:
                    continue
                start, end = line_range
                lookup[(file, start, end)] = f"scip:{occ.symbol}"
    return lookup, had_failures


def _codeql_language_for_project(project: Project) -> str | None:  # noqa: PLR0911 - one early-return per language is the clearest expression
    """Return the CodeQL language token for ``project``, or None if unsupported."""
    if project.kind is ProjectKind.NODE and project.languages.intersection(
        {"javascript", "typescript"}
    ):
        return "javascript"
    if project.kind is ProjectKind.PYTHON and "python" in project.languages:
        return "python"
    if project.kind is ProjectKind.JAVA and project.languages.intersection({"java", "kotlin"}):
        # CodeQL's ``java-kotlin`` extractor analyses both .java and .kt
        # source, so a Kotlin-only Gradle project (build.gradle.kts +
        # ``src/main/kotlin/...``) still wants the Java pipeline.
        return "java"
    if project.kind is ProjectKind.GO and "go" in project.languages:
        return "go"
    if project.kind is ProjectKind.RUBY and "ruby" in project.languages:
        return "ruby"
    if project.kind is ProjectKind.CSHARP and "csharp" in project.languages:
        return "csharp"
    return None


def _render_codeql_extension_packs(repo_dir: Path) -> list[Path]:
    """Render the per-language CodeQL extension YAMLs from the JSON sidecar.

    Phase 11: the model-proposal flow appends sinks to
    ``<repo_dir>/aics-codeql-extension-packs.json`` (promoted) +
    ``...staged.json`` (staged, NOT loaded at scan time). At scan time we
    emit per-language YAML files into ``<repo_dir>/codeql/model-packs/<lang>/``
    and return the language dirs so ``run_queries`` can pass them as
    ``--model-packs``. Missing or empty sidecar → empty list.
    """
    promoted = repo_dir / "aics-codeql-extension-packs.json"
    if not promoted.is_file():
        return []
    out_dir = repo_dir / "codeql" / "model-packs"
    written = render_codeql_yaml_extensions(promoted, out_dir=out_dir)
    if not written:
        return []
    # Each YAML lives at ``<out_dir>/<language>/extension.yml``; the language
    # dir is what `--model-packs` expects.
    lang_dirs = sorted({path.parent for path in written})
    return list(lang_dirs)


def _run_codeql_for_projects(  # noqa: PLR0913 - five positional data inputs; policy is keyword-only
    snapshot_root: Path,
    projects: list[Project],
    repo_dir: Path,
    bug_classes: list[BugClass] | None,
    conn,
    *,
    strict: bool,
) -> bool:
    """Run CodeQL and return whether available projects failed in fallback mode."""
    tags: list[str] = []
    if bug_classes:
        for c in bug_classes:
            tags.extend(c.codeql_tags)
    extension_packs = _render_codeql_extension_packs(repo_dir) or None
    had_failures = False
    for project in projects:
        language = _codeql_language_for_project(project)
        if language is None:
            continue
        if shutil.which("codeql") is None:
            if strict:
                raise RuntimeError("codeql engine requested but codeql is not on PATH")
            log.warning("codeql unavailable for %s; hybrid fallback remains active", project.name)
            continue
        project_id = project_artifact_id(project.name, project.base_path)
        try:
            db_path = build_database(
                snapshot_root / project.base_path,
                cache_dir=repo_dir,
                project_id=project_id,
                language=language,
            )
            # Filter extension packs to those matching this project's language.
            # ``run_queries`` will pass each as ``--model-packs <dir>``; passing
            # a Java pack to a Python scan would either no-op or fail
            # depending on CodeQL CLI version, so we pre-filter.
            project_packs: list[Path] | None
            if extension_packs:
                project_packs = [p for p in extension_packs if p.name == language]
                project_packs = project_packs or None
            else:
                project_packs = None
            result = run_queries(
                db_path,
                cache_dir=repo_dir,
                project_id=project_id,
                codeql_tags=tags,
                language=language,
                extension_packs=project_packs,
            )
            ingest_sarif(
                conn,
                sarif_path=result.sarif_path,
                project_id=project_id,
                snapshot_root=snapshot_root,
                engine="codeql",
            )
        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
            if strict:
                raise RuntimeError(f"codeql failed for {project.name}: {exc}") from exc
            log.warning("codeql failed for %s: %s", project.name, exc)
            had_failures = True
    return had_failures


def _mark_prep_started(repo_dir: Path) -> bool:
    """Write the crash marker and return whether an earlier attempt left it behind."""
    marker = repo_dir / _PREP_INCOMPLETE_MARKER
    was_incomplete = marker.is_file()
    temporary = marker.with_suffix(".tmp")
    temporary.write_text("prep in progress\n", encoding="utf-8")
    temporary.replace(marker)
    return was_incomplete


def _index_projects(
    conn: duckdb.DuckDBPyConnection,
    *,
    snapshot_root: Path,
    projects: list[Project],
    scip_lookup: dict,
) -> None:
    indexed_ast_files: set[tuple[str, Path]] = set()
    for project in projects:
        jobs = _deduplicate_ast_jobs(
            _ast_jobs_for_project(snapshot_root, project),
            indexed_ast_files,
        )
        if not jobs:
            continue
        files: list[dict] = []
        symbols: list[dict] = []
        xrefs: list[dict] = []
        for record in run_jobs(jobs):
            record_type = record["type"]
            if record_type == "file":
                files.append(record)
            elif record_type == "symbol":
                symbols.append(record)
            elif record_type == "xref":
                xrefs.append(record)
        duckdb_ingest(
            conn,
            files=files,
            symbols=symbols,
            xrefs=xrefs,
            scip_lookup=scip_lookup,
            project_id=project.name,
            snapshot_root=snapshot_root,
        )
        ingest_entrypoints(conn, detect_entrypoints(xrefs=xrefs, symbols=symbols))


def _entrypoints_from_index(conn: duckdb.DuckDBPyConnection) -> list[Entrypoint]:
    rows = conn.execute("SELECT symbol_id, kind, signature, file, line FROM entrypoints").fetchall()
    return [
        Entrypoint(
            symbol_id=symbol_id,
            kind=kind,
            signature=signature,
            file=file or "",
            line=int(line or 0),
        )
        for symbol_id, kind, signature, file, line in rows
    ]


def _write_text_atomic(path: Path, content: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _emit_index_artifacts(  # noqa: PLR0913 - one positional arg; artifact context is keyword-only
    conn: duckdb.DuckDBPyConnection,
    *,
    target_name: str,
    projects: list[Project],
    snapshot_root: Path,
    artifact_root: Path,
) -> None:
    _write_text_atomic(
        artifact_root / "repo.md",
        render_repo_md(target_name=target_name, projects=projects),
    )
    _write_text_atomic(
        artifact_root / "entrypoints.md",
        render_entrypoints_md(
            target_name=target_name,
            entrypoints=_entrypoints_from_index(conn),
        ),
    )
    sidecars_root = artifact_root / "sidecars"
    sidecars_root.mkdir(parents=True, exist_ok=True)
    emit_sidecars(conn, snapshot_root=snapshot_root, sidecars_root=sidecars_root)


def _promote_index_artifacts(artifact_root: Path, repo_dir: Path) -> None:
    """Publish staged projections only after the DuckDB transaction commits."""
    for name in ("repo.md", "entrypoints.md"):
        (artifact_root / name).replace(repo_dir / name)
    staged_sidecars = artifact_root / "sidecars"
    live_sidecars = repo_dir / "sidecars"
    backup_sidecars = repo_dir / ".sidecars.previous"
    if backup_sidecars.exists():
        shutil.rmtree(backup_sidecars)
    if live_sidecars.exists():
        live_sidecars.replace(backup_sidecars)
    try:
        staged_sidecars.replace(live_sidecars)
    except BaseException:
        if backup_sidecars.exists() and not live_sidecars.exists():
            backup_sidecars.replace(live_sidecars)
        raise
    if backup_sidecars.exists():
        shutil.rmtree(backup_sidecars)


def _rebuild_source_index(  # noqa: PLR0913 - one positional arg; scan context is keyword-only
    conn: duckdb.DuckDBPyConnection,
    *,
    snapshot_root: Path,
    projects: list[Project],
    repo_dir: Path,
    bug_classes: list[BugClass] | None,
    engine: str,
) -> bool:
    _clear_source_index(conn)
    scip_lookup, had_gaps = _build_scip_lookup(snapshot_root, projects, repo_dir)
    _index_projects(
        conn,
        snapshot_root=snapshot_root,
        projects=projects,
        scip_lookup=scip_lookup,
    )
    if engine in {"codeql", "hybrid"}:
        had_gaps = (
            _run_codeql_for_projects(
                snapshot_root,
                projects,
                repo_dir,
                bug_classes,
                conn,
                strict=engine == "codeql",
            )
            or had_gaps
        )
    return had_gaps


def _prepare_index(  # noqa: PLR0913 - transaction inputs are keyword-only orchestration state
    *,
    db_path: Path,
    db_existed: bool,
    fingerprint: str,
    engine: str,
    force: bool,
    previous_attempt_failed: bool,
    snapshot: SnapshotResult,
    projects: list[Project],
    repo_dir: Path,
    target_name: str,
    bug_classes: list[BugClass] | None,
    artifact_root: Path,
    quiet: bool,
) -> bool:
    conn = duckdb.connect(str(db_path))
    try:
        apply_schema(conn)
        incremental = (
            not force
            and not previous_attempt_failed
            and snapshot.skipped
            and db_existed
            and scan_stage_is_current(
                conn,
                fingerprint=fingerprint,
                engine=engine,
                required_stage="prep",
            )
        )
        if incremental:
            if not quiet:
                log.info("skipping AST/SCIP/CodeQL stages — cached results reused")
            _emit_index_artifacts(
                conn,
                target_name=target_name,
                projects=projects,
                snapshot_root=snapshot.snapshot_dir,
                artifact_root=artifact_root,
            )
            return True
        conn.execute("BEGIN TRANSACTION")
        try:
            had_gaps = _rebuild_source_index(
                conn,
                snapshot_root=snapshot.snapshot_dir,
                projects=projects,
                repo_dir=repo_dir,
                bug_classes=bug_classes,
                engine=engine,
            )
            _emit_index_artifacts(
                conn,
                target_name=target_name,
                projects=projects,
                snapshot_root=snapshot.snapshot_dir,
                artifact_root=artifact_root,
            )
            if engine in {"hybrid", "llm-heavy"}:
                stage = "prep_with_gaps" if had_gaps else "prep"
            else:
                stage = "complete_with_gaps" if had_gaps else "complete"
            set_scan_stage(conn, fingerprint=fingerprint, engine=engine, stage=stage)
            conn.execute("COMMIT")
        except BaseException:
            with suppress(duckdb.Error):
                conn.execute("ROLLBACK")
            raise
        return False
    finally:
        conn.close()


def run_prep(  # noqa: PLR0913 - keyword-only orchestration knobs
    target: Path,
    *,
    cache_root: Path,
    commit: str | None = None,
    bug_classes: list[BugClass] | None = None,
    engine: str = "codeql",
    llm_provider: str = "claude",
    llm_model: str = "",
    quiet: bool = False,
    force: bool = False,
) -> tuple[SnapshotResult, Path]:
    """Snapshot, detect, AST, SCIP, ingest. Returns the snapshot result and the duckdb path.

    Reuse requires both a matching snapshot and a complete scanner/config fingerprint.
    A failed rebuild rolls back source-derived rows and leaves a crash marker that forces
    the next invocation to retry. Pass ``force=True`` to bypass reuse explicitly.
    """
    repo_dir = cache_root / compute_repo_id(target)
    repo_dir.mkdir(parents=True, exist_ok=True)
    with repo_scan_lock(repo_dir):
        previous_attempt_failed = _mark_prep_started(repo_dir)
        snap = take_snapshot(target, cache_dir=repo_dir, commit=commit)
        projects = detect_projects(snap.snapshot_dir)
        fingerprint = build_scan_fingerprint(
            repo_dir,
            engine=engine,
            bug_classes=bug_classes,
            engine_config=(
                {"llm_provider": llm_provider, "llm_model": llm_model}
                if engine == "llm-heavy"
                else None
            ),
        )
        db_path = repo_dir / "index.duckdb"
        db_existed = db_path.is_file()
        artifact_root = Path(tempfile.mkdtemp(prefix=".prep-artifacts-", dir=repo_dir))
        try:
            incremental = _prepare_index(
                db_path=db_path,
                db_existed=db_existed,
                fingerprint=fingerprint,
                engine=engine,
                force=force,
                previous_attempt_failed=previous_attempt_failed,
                snapshot=snap,
                projects=projects,
                repo_dir=repo_dir,
                target_name=target.name,
                bug_classes=bug_classes,
                artifact_root=artifact_root,
                quiet=quiet,
            )
            _promote_index_artifacts(artifact_root, repo_dir)
        finally:
            if artifact_root.exists():
                shutil.rmtree(artifact_root)
        (repo_dir / _PREP_INCOMPLETE_MARKER).unlink(missing_ok=True)
        return replace(snap, index_reused=incremental), db_path
