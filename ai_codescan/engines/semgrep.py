"""Semgrep engine wrapper.

Runs ``semgrep --config=auto --sarif`` against a project. SARIF output is
ingested into the same ``flows`` table the CodeQL engine writes to, with
``engine='semgrep'`` so the hybrid engine can dedupe.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class SemgrepUnavailableError(RuntimeError):
    """Raised when ``semgrep`` isn't on PATH."""


def is_available() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(
    project_root: Path,
    *,
    cache_dir: Path,
    project_id: str,
    config: str = "auto",
    timeout: int = 600,
) -> Path:
    """Run semgrep against ``project_root``; emit SARIF to the cache.

    Returns the path to the SARIF file. ``config='auto'`` uses Semgrep's
    default rule registry (Semgrep CE; OSS rules only).
    """
    if not is_available():
        raise SemgrepUnavailableError(
            "semgrep is not on PATH; pip install semgrep or skip --engine hybrid."
        )
    sarif_dir = cache_dir / "semgrep"
    sarif_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = sarif_dir / f"{project_id}.sarif"
    subprocess.run(  # noqa: S603 - argv-only, no shell
        [  # noqa: S607
            "semgrep",
            "scan",
            f"--config={config}",
            "--sarif",
            "--output",
            str(sarif_path),
            str(project_root),
        ],
        check=False,  # semgrep exits non-zero on findings; that's not an error
        capture_output=True,
        timeout=timeout,
    )
    return sarif_path
