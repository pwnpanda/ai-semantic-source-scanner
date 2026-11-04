"""Spawn the AST workers and stream their JSONL output.

Most languages are extracted by the Node worker (tree-sitter / ts-morph).
Perl has its own worker built on PPI because no tree-sitter Perl grammar is
ABI compatible with the pinned ``tree-sitter@0.22.4`` host binding. Both
workers speak the same JSONL protocol, so the only difference is which
interpreter is spawned.
"""

from __future__ import annotations

import functools
import json
import logging
import shutil
import subprocess
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

log = logging.getLogger(__name__)

WORKER_DIR = Path(__file__).resolve().parent / "node_worker"
PERL_WORKER = Path(__file__).resolve().parent / "perl_worker" / "extract_perl.pl"

# Job kinds handled by the PPI-based Perl worker rather than the Node worker.
_PERL_KINDS = frozenset({"perl"})


@functools.cache
def perl_worker_available() -> bool:
    """Return True when ``perl`` and the PPI module are both usable.

    PPI is an optional dependency: it is only needed to index Perl sources.
    A repository in another language that happens to carry a stray ``.pl``
    helper must still prep successfully on a host without PPI, so callers
    skip Perl jobs rather than failing the scan.
    """
    if shutil.which("perl") is None:
        return False
    try:
        # S603/S607: argv-only, no shell; literal interpreter on PATH.
        result = subprocess.run(  # noqa: S603
            ["perl", "-MPPI", "-e1"],  # noqa: S607
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0


@dataclass(frozen=True, slots=True)
class AstJob:
    """One worker job."""

    kind: Literal[
        "ts",
        "html",
        "treesitter",
        "python",
        "java",
        "go",
        "ruby",
        "php",
        "csharp",
        "kotlin",
        "bash",
        "yaml",
        "perl",
    ]
    project_root: Path
    files: list[Path] = field(default_factory=list)
    tsconfig: Path | None = None


def _job_to_dict(job: AstJob, job_id: int) -> dict[str, Any]:
    return {
        "jobId": job_id,
        "kind": job.kind,
        "projectRoot": str(job.project_root),
        "files": [str(f) for f in job.files],
        "tsconfig": str(job.tsconfig) if job.tsconfig else None,
    }


def _run_worker(argv: list[str], job_list: list[AstJob]) -> Iterator[dict[str, Any]]:
    """Feed ``job_list`` to one worker process and yield its data records.

    The worker emits one ``done`` record per job; this function consumes
    those without yielding them so consumers see only data records.
    """
    if not job_list:
        return
    # S603: argv list with a literal interpreter name on PATH; all arguments
    # are constructed locally (no shell) and the worker script path is
    # derived from this module's location.
    proc = subprocess.Popen(  # noqa: S603
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("subprocess pipes failed to open")

    for idx, job in enumerate(job_list):
        proc.stdin.write(json.dumps(_job_to_dict(job, idx)) + "\n")
    proc.stdin.flush()
    proc.stdin.close()

    expected_done = len(job_list)
    seen_done = 0
    for line in proc.stdout:
        record: dict[str, Any] = json.loads(line)
        if record.get("type") == "done":
            seen_done += 1
            if seen_done >= expected_done:
                break
            continue
        if record.get("type") == "error":
            proc.wait(timeout=5)
            raise RuntimeError(f"AST worker error: {record.get('message')}")
        yield record

    rc = proc.wait(timeout=10)
    stderr = proc.stderr.read() if proc.stderr else ""
    if rc != 0:
        raise RuntimeError(f"AST worker exited {rc}: {stderr}")


def run_jobs(jobs: Iterable[AstJob]) -> Iterator[dict[str, Any]]:
    """Run each job through the worker that owns its language.

    Perl jobs go to the PPI worker; everything else goes to the Node worker.
    Both speak the same JSONL protocol, so callers see one uniform stream.
    """
    job_list = list(jobs)
    node_jobs = [job for job in job_list if job.kind not in _PERL_KINDS]
    perl_jobs = [job for job in job_list if job.kind in _PERL_KINDS]

    yield from _run_worker(["node", str(WORKER_DIR / "worker.mjs")], node_jobs)

    if perl_jobs and not perl_worker_available():
        # Degrade instead of failing: a polyglot repo with one .pl helper must
        # still prep on a host without PPI. The Perl files simply go
        # un-indexed, which prep reports as a coverage gap.
        file_count = sum(len(job.files) for job in perl_jobs)
        log.warning(
            "perl AST worker unavailable (needs perl + PPI); skipping %d Perl file(s). "
            "Install PPI to index them: apt-get install libppi-perl, or cpanm PPI.",
            file_count,
        )
        return
    yield from _run_worker(["perl", str(PERL_WORKER)], perl_jobs)
