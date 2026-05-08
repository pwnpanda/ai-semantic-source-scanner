"""Path and ID conventions for the cache layout.

repo_id format: ``<basename>-<sha1(canonical-path)[:8]>`` per design spec §8.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def _canonical_target_identity(target: Path) -> str:
    """Return the string used to derive the repo's hash component.

    Prefers ``git remote get-url origin`` when present; falls back to the
    absolute filesystem path so non-git directories still get a stable id.
    """
    if (target / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(target), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    return str(target.resolve())


def compute_repo_id(target: Path) -> str:
    """Stable identifier for ``target`` of the form ``<basename>-<sha1[:8]>``."""
    basename = target.name
    identity = _canonical_target_identity(target)
    digest = hashlib.sha1(identity.encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"{basename}-{digest[:8]}"


def default_cache_root() -> Path:
    """Default location for all per-repo cache trees."""
    return Path.home() / ".ai_codescan" / "repos"


def repo_cache_dir(target: Path, *, cache_root: Path | None = None) -> Path:
    """Cache directory for ``target`` under ``cache_root`` (default: ``~/.ai_codescan/repos``)."""
    root = cache_root if cache_root is not None else default_cache_root()
    return root / compute_repo_id(target)
