"""Wrap the CodeQL CLI: build database, run queries, emit SARIF."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml

QUERY_SUITE = "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"
"""Default suite that includes most security queries.

Resolved as a CodeQL pack-qualified path; the bare ``.qls`` name is not
recognised by ``codeql database analyze``. The pack is downloaded on first
use via ``codeql pack download codeql/javascript-queries`` (auto-fetched
when not present in ``~/.codeql/packages``)."""


def _ensure_codeql_on_path() -> None:
    if shutil.which("codeql") is None:
        raise RuntimeError(
            "codeql CLI not on PATH. Install from github.com/github/codeql-cli."
        )


def build_database(
    project_root: Path,
    *,
    cache_dir: Path,
    project_id: str,
    allow_minified: bool = False,
) -> Path:
    """Build a CodeQL DB for ``project_root`` rooted at ``cache_dir``.

    Returns the path to the database directory.
    """
    _ensure_codeql_on_path()
    db_path = cache_dir / "codeql" / f"{project_id}.db"
    if db_path.exists():
        shutil.rmtree(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    if allow_minified:
        env["CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES"] = "true"
    # S603/S607: argv list with literal "codeql" on PATH; all arguments are
    # constructed locally (no shell) and the inputs are validated paths.
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "codeql",
            "database",
            "create",
            str(db_path),
            "--language=javascript-typescript",
            "--source-root",
            str(project_root),
            "--overwrite",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    return db_path


@dataclass(frozen=True, slots=True)
class CodeqlResult:
    """Output of a CodeQL analysis run."""

    sarif_path: Path
    db_path: Path
    project_id: str


def _write_tag_filtered_suite(suite_path: Path, codeql_tags: list[str]) -> None:
    """Write a CodeQL query-suite YAML that runs the security-extended
    queries from ``codeql/javascript-queries`` filtered to those whose
    ``@tags`` intersect ``codeql_tags``.

    A suite is a sequence of single-key instructions. ``queries: .`` plus
    ``qlpack:`` selects all queries in the pack; the ``include`` instruction
    keeps only queries whose tags match. Equivalent to a hand-written
    ``.qls`` such as those in ``codeql/javascript-queries/codeql-suites/``.
    """
    instructions: list[dict[str, object]] = [
        {"description": "ai-codescan tag-filtered security suite"},
        {"queries": ".", "from": "codeql/javascript-queries"},
        {"include": {"tags contain": list(codeql_tags)}},
        {"exclude": {"deprecated": "//"}},
    ]
    suite_path.write_text(yaml.safe_dump(instructions, sort_keys=False))


def run_queries(
    db_path: Path,
    *,
    cache_dir: Path,
    project_id: str,
    codeql_tags: list[str],
    extension_packs: list[Path] | None = None,
) -> CodeqlResult:
    """Run the security suite filtered by ``codeql_tags`` and emit SARIF.

    When ``codeql_tags`` is empty the full security suite runs; otherwise a
    transient ``.qls`` file is generated that filters by ``@tags``.
    """
    _ensure_codeql_on_path()
    sarif_dir = cache_dir / "codeql"
    sarif_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = sarif_dir / f"{project_id}.sarif"

    if codeql_tags:
        suite_path = sarif_dir / f"{project_id}.filter.qls"
        _write_tag_filtered_suite(suite_path, codeql_tags)
        suite_arg: str = str(suite_path)
    else:
        suite_arg = QUERY_SUITE

    cmd = [
        "codeql",
        "database",
        "analyze",
        str(db_path),
        "--format=sarifv2.1.0",
        "--output",
        str(sarif_path),
        "--sarif-add-query-help",
    ]
    if extension_packs:
        for pack in extension_packs:
            cmd += ["--model-packs", str(pack)]
    cmd.append(suite_arg)

    # S603/S607: argv list with literal "codeql" on PATH; arguments are
    # constructed locally (no shell), with validated paths and tag strings.
    subprocess.run(cmd, check=True, capture_output=True)  # noqa: S603
    return CodeqlResult(sarif_path=sarif_path, db_path=db_path, project_id=project_id)
