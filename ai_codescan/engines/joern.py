"""Joern engine wrapper.

Joern is a JVM-based tool (~2 GB install) that produces a Code Property
Graph (CPG). When ``joern`` is on PATH, this module:

1. Builds a CPG with ``joern-parse <project_root> -o <cpg.bin>``
2. Runs ``joern --script <joern_queries.sc>`` against it to scan for taint
   flows from common JS/TS sources to common sinks (``query``, ``exec``,
   ``res.send``, ``fs.readFile``).
3. Returns the path to a JSONL file with one record per flow.

The flows produced by this module are merged into the same DuckDB ``flows``
table the orchestrator uses for CodeQL and Semgrep, tagged ``engine='joern'``.
The hybrid engine then dedupes overlapping findings.

If ``joern`` isn't on PATH, :func:`run_joern` raises :class:`JoernUnavailableError`
and the hybrid engine continues without it. Install with::

    bash scripts/install.sh   # answers `yes` to the Joern prompt
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

QUERIES_SCRIPT = Path(__file__).resolve().parent / "joern_queries.sc"

_JOERN_LANGUAGE_FLAG: dict[str, str] = {
    # Token passed to ``joern-parse --language``. Keep frontend-specific
    # tokens here so callers stay in scanner-language terms.
    # - ``pythonsrc`` selects the modern ``pysrc2cpg`` frontend; ``python``
    #   would pick the legacy ``python2cpg`` which produces a less faithful CPG.
    # - ``JAVASRC`` selects the source frontend (``javasrc2cpg``); ``JAVA``
    #   would pick the bytecode frontend (``jimple2cpg``).
    "javascript": "javascript",
    "python": "pythonsrc",
    "java": "JAVASRC",
    "go": "GOLANG",
    # Joern's rubysrc2cpg frontend is officially marked as beta — it parses
    # most modern Ruby (1.8 through 3.2) via the parser gem but produces less
    # complete CPGs than the JS/Python/Java frontends; metaprogramming
    # (``send``, ``method_missing``, ``define_method``) routinely shows up
    # as unresolved call edges. The wiring is identical to the others; the
    # caller is responsible for handling parse failures gracefully.
    "ruby": "RUBYSRC",
    # Joern's php2cpg shells out to PHP-Parser, so the host needs ``php`` on
    # PATH. Document this as a runtime requirement; the call still gracefully
    # fails via JoernUnavailableError when ``joern-parse`` itself is missing.
    "php": "PHP",
}

_SOURCE_EXTS_BY_LANGUAGE: dict[str, frozenset[str]] = {
    "javascript": frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}),
    "python": frozenset({".py", ".pyi"}),
    "java": frozenset({".java"}),
    "go": frozenset({".go"}),
    "ruby": frozenset({".rb", ".rake"}),
    "php": frozenset({".php", ".phtml"}),
}


class JoernUnavailableError(RuntimeError):
    """Raised when ``joern`` isn't on PATH."""


def is_available() -> bool:
    """Return True if all three Joern binaries we need are on PATH."""
    return all(shutil.which(b) is not None for b in ("joern", "joern-parse"))


def _build_cpg(
    project_root: Path,
    *,
    cache_dir: Path,
    project_id: str,
    language: str = "javascript",
) -> Path:
    """Run ``joern-parse`` to produce ``<cache>/joern/<project_id>.cpg.bin``.

    Cached: re-uses an existing CPG when its mtime is newer than every source
    file under ``project_root``. CPG builds are slow (30-90s on a 50k-LOC repo).
    """
    if language not in _JOERN_LANGUAGE_FLAG:
        raise ValueError(f"unsupported joern language: {language!r}")
    out_dir = cache_dir / "joern"
    out_dir.mkdir(parents=True, exist_ok=True)
    cpg_path = out_dir / f"{project_id}.cpg.bin"

    source_exts = _SOURCE_EXTS_BY_LANGUAGE[language]
    if cpg_path.is_file():
        cpg_mtime = cpg_path.stat().st_mtime
        sources = (p for p in project_root.rglob("*") if p.is_file() and p.suffix in source_exts)
        if all(p.stat().st_mtime <= cpg_mtime for p in sources):
            return cpg_path

    subprocess.run(  # noqa: S603 - argv-only, no shell
        [  # noqa: S607
            "joern-parse",
            str(project_root),
            "--language",
            _JOERN_LANGUAGE_FLAG[language],
            "-o",
            str(cpg_path),
        ],
        check=True,
        capture_output=True,
        timeout=600,  # 10 min cap; bigger projects need a bigger budget
    )
    return cpg_path


def _run_query_script(cpg_path: Path, *, cache_dir: Path, project_id: str, language: str) -> Path:
    """Run the bundled Joern query script against ``cpg_path``; return JSONL path.

    The script reads ``language`` to pick language-appropriate source/sink
    patterns; flow shape and JSON keys are language-independent.
    """
    out_dir = cache_dir / "joern"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{project_id}.flows.jsonl"
    if not QUERIES_SCRIPT.is_file():
        raise RuntimeError(f"missing Joern query script at {QUERIES_SCRIPT}")
    out_path.write_text("", encoding="utf-8")  # truncate stale output

    subprocess.run(  # noqa: S603 - argv-only, no shell
        [  # noqa: S607
            "joern",
            "--script",
            str(QUERIES_SCRIPT),
            "--param",
            f"cpgPath={cpg_path}",
            "--param",
            f"outPath={out_path}",
            "--param",
            f"language={language}",
        ],
        check=True,
        capture_output=True,
        timeout=300,
    )
    return out_path


def run_joern(
    project_root: Path,
    *,
    cache_dir: Path,
    project_id: str,
    language: str = "javascript",
) -> Path:
    """Run Joern against ``project_root`` and emit a flows JSONL.

    Returns the path to the JSONL output. Each line is a ``Flow`` record:
    ``{fid, source_file, source_line, sink_file, sink_line, source_name,
    sink_name, cwe, sink_class, parameterization}``. Empty file means "no
    flows found" — that's a valid result, not an error.
    """
    if not is_available():
        raise JoernUnavailableError(
            "joern / joern-parse not on PATH. Install via "
            "`bash scripts/install.sh` (answer yes to the Joern prompt) or "
            "https://docs.joern.io/installation"
        )
    cpg_path = _build_cpg(
        project_root, cache_dir=cache_dir, project_id=project_id, language=language
    )
    return _run_query_script(
        cpg_path, cache_dir=cache_dir, project_id=project_id, language=language
    )


def parse_flows(jsonl_path: Path) -> list[dict[str, object]]:
    """Parse the JSONL file emitted by :func:`run_joern` into flow dicts."""
    if not jsonl_path.is_file():
        return []
    out: list[dict[str, object]] = []
    for raw in jsonl_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
