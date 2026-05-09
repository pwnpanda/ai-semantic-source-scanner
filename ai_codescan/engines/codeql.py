"""Wrap the CodeQL CLI: build database, run queries, emit SARIF."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml

_QUERY_SUITES: dict[str, str] = {
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
    "go": "codeql/go-queries:codeql-suites/go-security-extended.qls",
    "ruby": "codeql/ruby-queries:codeql-suites/ruby-security-extended.qls",
}
"""Per-language default suite — security-extended is the broadest stable set.

Resolved as a CodeQL pack-qualified path; the bare ``.qls`` name is not
recognised by ``codeql database analyze``. The pack is downloaded on first
use via ``codeql pack download <pack>`` (auto-fetched when not present in
``~/.codeql/packages``)."""

_QUERY_PACKS: dict[str, str] = {
    "javascript": "codeql/javascript-queries",
    "python": "codeql/python-queries",
    "java": "codeql/java-queries",
    "go": "codeql/go-queries",
    "ruby": "codeql/ruby-queries",
}

_CODEQL_LANGUAGE_FLAG: dict[str, str] = {
    # Value passed to ``codeql database create --language=...``.
    # JS and TS share an extractor; Python is its own language; Java's
    # extractor analyses Kotlin too when present; Go is a single token;
    # Ruby is bare-source (no toolchain on host required).
    "javascript": "javascript-typescript",
    "python": "python",
    "java": "java-kotlin",
    "go": "go",
    "ruby": "ruby",
}

# Languages whose extractor needs ``--build-mode=none`` to extract source
# without an external build (CodeQL CLI ≥ 2.18.2). JS/Python don't accept
# this flag; Java/Kotlin require *some* build mode and ``none`` is the
# zero-config option.
_CODEQL_BUILD_MODE_LANGS: frozenset[str] = frozenset({"java"})

QUERY_SUITE = _QUERY_SUITES["javascript"]
"""Default JavaScript suite — kept as a public alias for back-compat."""


def _ensure_codeql_on_path() -> None:
    if shutil.which("codeql") is None:
        raise RuntimeError("codeql CLI not on PATH. Install from github.com/github/codeql-cli.")


def build_database(
    project_root: Path,
    *,
    cache_dir: Path,
    project_id: str,
    allow_minified: bool = False,
    language: str = "javascript",
) -> Path:
    """Build a CodeQL DB for ``project_root`` rooted at ``cache_dir``.

    ``language`` selects the extractor; one of ``javascript`` (covers JS+TS)
    or ``python``. Returns the path to the database directory.
    """
    _ensure_codeql_on_path()
    if language not in _CODEQL_LANGUAGE_FLAG:
        raise ValueError(f"unsupported codeql language: {language!r}")
    db_path = cache_dir / "codeql" / f"{project_id}.db"
    if db_path.exists():
        shutil.rmtree(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    if allow_minified and language == "javascript":
        env["CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES"] = "true"
    cmd = [
        "codeql",
        "database",
        "create",
        str(db_path),
        f"--language={_CODEQL_LANGUAGE_FLAG[language]}",
        "--source-root",
        str(project_root),
        "--overwrite",
    ]
    if language in _CODEQL_BUILD_MODE_LANGS:
        # ``none`` produces less precise results than a real build (no
        # annotation-processor output, no private-registry deps), but it
        # avoids requiring Maven/Gradle on the scanner host.
        cmd.append("--build-mode=none")
    # S603/S607: argv list with literal "codeql" on PATH; all arguments are
    # constructed locally (no shell) and the inputs are validated paths.
    subprocess.run(  # noqa: S603
        cmd,  # noqa: S607
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


def _write_tag_filtered_suite(
    suite_path: Path,
    codeql_tags: list[str],
    *,
    language: str = "javascript",
) -> None:
    """Write a CodeQL query-suite YAML that runs the security-extended
    queries from the language-appropriate query pack filtered to those
    whose ``@tags`` intersect ``codeql_tags``.

    A suite is a sequence of single-key instructions. ``queries: .`` plus
    ``qlpack:`` selects all queries in the pack; the ``include`` instruction
    keeps only queries whose tags match. Equivalent to a hand-written
    ``.qls`` such as those in ``codeql/<lang>-queries/codeql-suites/``.
    """
    pack = _QUERY_PACKS.get(language)
    if pack is None:
        raise ValueError(f"unsupported codeql language: {language!r}")
    instructions: list[dict[str, object]] = [
        {"description": "ai-codescan tag-filtered security suite"},
        {"queries": ".", "from": pack},
        {"include": {"tags contain": list(codeql_tags)}},
        {"exclude": {"deprecated": "//"}},
    ]
    suite_path.write_text(yaml.safe_dump(instructions, sort_keys=False))


def run_queries(  # noqa: PLR0913 - keyword-only knobs are clearer than packing into a config object
    db_path: Path,
    *,
    cache_dir: Path,
    project_id: str,
    codeql_tags: list[str],
    extension_packs: list[Path] | None = None,
    language: str = "javascript",
) -> CodeqlResult:
    """Run the security suite filtered by ``codeql_tags`` and emit SARIF.

    When ``codeql_tags`` is empty the full security suite runs; otherwise a
    transient ``.qls`` file is generated that filters by ``@tags``.
    ``language`` selects which query pack to draw from.
    """
    _ensure_codeql_on_path()
    if language not in _QUERY_SUITES:
        raise ValueError(f"unsupported codeql language: {language!r}")
    sarif_dir = cache_dir / "codeql"
    sarif_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = sarif_dir / f"{project_id}.sarif"

    if codeql_tags:
        suite_path = sarif_dir / f"{project_id}.filter.qls"
        _write_tag_filtered_suite(suite_path, codeql_tags, language=language)
        suite_arg: str = str(suite_path)
    else:
        suite_arg = _QUERY_SUITES[language]

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
