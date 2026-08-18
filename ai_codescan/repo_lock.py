"""Advisory serialization for scan state belonging to one cached repository."""

from __future__ import annotations

import fcntl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

_LOCK_NAME = ".scan.lock"
_thread_state = threading.local()


class RepoScanLockedError(RuntimeError):
    """Raised when another process is already mutating a repository cache."""


def _held_locks() -> dict[Path, tuple[TextIO, int]]:
    held = getattr(_thread_state, "held", None)
    if held is None:
        held = {}
        _thread_state.held = held
    return held


@contextmanager
def repo_scan_lock(repo_dir: Path) -> Iterator[None]:
    """Hold a fail-fast exclusive lock across a repo cache mutation.

    Locks are re-entrant within one thread so a CLI workflow can protect the
    whole scan while the individual prep and engine entry points remain safe
    when called directly.

    Args:
        repo_dir: Cache directory whose mutable scan state is protected.

    Raises:
        RepoScanLockedError: Another thread or process owns the repo lock.
    """
    repo_dir.mkdir(parents=True, exist_ok=True)
    lock_path = (repo_dir / _LOCK_NAME).resolve()
    held = _held_locks()
    if lock_path in held:
        handle, depth = held[lock_path]
        held[lock_path] = (handle, depth + 1)
        try:
            yield
        finally:
            held[lock_path] = (handle, depth)
        return

    handle = lock_path.open("a+")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RepoScanLockedError(
                f"scan already in progress for cached repository: {repo_dir}"
            ) from exc
        held[lock_path] = (handle, 1)
        try:
            yield
        finally:
            held.pop(lock_path, None)
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()
