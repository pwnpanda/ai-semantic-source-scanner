"""Semgrep engine wrapper.

Runs ``semgrep --config=auto --sarif`` against a project. SARIF output is
ingested into the same ``flows`` table the CodeQL engine writes to, with
``engine='semgrep'`` so the hybrid engine can dedupe.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

_BUNDLED_RULES_DIR = Path(__file__).parent / "semgrep_rules"
"""Directory of project-specific rules shipped with ai-codescan. Always
passed to semgrep alongside ``--config=auto`` so we extend (not replace)
the community ruleset with patterns the OSS pack misses (e.g. CWE-208
timing-attack on env-var secrets)."""


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
    default rule registry (Semgrep CE; OSS rules only). The bundled
    rules under ``semgrep_rules/`` are appended so security gaps in the
    community pack (e.g. CWE-208 timing-attack on ``process.env``) get
    matched too.
    """
    if not is_available():
        raise SemgrepUnavailableError(
            "semgrep is not on PATH; pip install semgrep or skip --engine hybrid."
        )
    sarif_dir = cache_dir / "semgrep"
    sarif_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = sarif_dir / f"{project_id}.sarif"
    cmd = [
        "semgrep",
        "scan",
        f"--config={config}",
        "--sarif",
        "--output",
        str(sarif_path),
    ]
    if _BUNDLED_RULES_DIR.is_dir() and any(_BUNDLED_RULES_DIR.glob("*.yaml")):
        cmd.append(f"--config={_BUNDLED_RULES_DIR}")
    cmd.append(str(project_root))
    subprocess.run(  # noqa: S603 - argv-only, no shell
        cmd,  # noqa: S607
        check=False,  # semgrep exits non-zero on findings; that's not an error
        capture_output=True,
        timeout=timeout,
    )
    return sarif_path
