"""Joern engine wrapper (stub).

Joern is a JVM-based tool (~1.5 GB install) that produces a Code Property
Graph (CPG). When available, this module runs ``joern-parse`` + ``joern``
to dump security findings as flow records.

Phase 3A ships the wiring; the actual Joern install is opt-in. To enable:

    curl -L https://github.com/joernio/joern/releases/latest/download/joern-install.sh | bash
    # add ~/joern-cli to PATH

If ``joern`` isn't on PATH, callers get :class:`JoernUnavailableError` and the
hybrid engine continues without it.
"""

from __future__ import annotations

import shutil
from pathlib import Path


class JoernUnavailableError(RuntimeError):
    """Raised when ``joern`` isn't on PATH."""


def is_available() -> bool:
    return shutil.which("joern") is not None


def run_joern(
    project_root: Path,
    *,
    cache_dir: Path,
    project_id: str,
) -> Path:
    """Run Joern against ``project_root`` and emit a flows-style JSONL.

    Phase 3A status: stubbed. When Joern is on PATH, the orchestrator currently
    skips this engine and only logs a warning. A full integration will:

    1. ``joern-parse <project_root> --output <cpg.bin>``
    2. drive ``joern --script flows.sc`` with a query that emits
       ``{tid, sid, cwe, source, sink, steps}`` JSONL.

    See ``docs/superpowers/specs/2026-05-09-ai-codescan-phase2-design.md`` §3
    (deferred to Phase 3) and the LLMxCPG paper (arxiv 2507.16585) for the
    target query patterns.
    """
    if not is_available():
        raise JoernUnavailableError(
            "joern is not on PATH; install via the official installer "
            "(https://docs.joern.io/installation) to enable --engine hybrid joern coverage."
        )
    out_dir = cache_dir / "joern"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{project_id}.flows.jsonl"
    out_path.write_text("", encoding="utf-8")
    return out_path
