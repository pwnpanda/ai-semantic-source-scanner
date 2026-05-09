"""Spawn the Node AST worker and stream its JSONL output."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

WORKER_DIR = Path(__file__).resolve().parent / "node_worker"


@dataclass(frozen=True, slots=True)
class AstJob:
    """One worker job."""

    kind: Literal["ts", "html", "treesitter", "python", "java"]
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


def run_jobs(jobs: Iterable[AstJob]) -> Iterator[dict[str, Any]]:
    """Run each job through the Node worker and yield raw record dicts.

    The worker emits one ``done`` record per job; this function consumes
    those without yielding them so consumers see only data records.
    """
    # S603/S607: argv list with literal "node" on PATH; all arguments are
    # constructed locally (no shell) and the worker script path is derived
    # from this module's location.
    proc = subprocess.Popen(  # noqa: S603
        ["node", str(WORKER_DIR / "worker.mjs")],  # noqa: S607
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("subprocess pipes failed to open")

    job_list = list(jobs)
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
