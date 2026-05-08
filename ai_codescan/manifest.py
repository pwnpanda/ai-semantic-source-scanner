"""File-content manifest used for snapshot integrity and incremental diffing."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

_HASH_BUF = 65_536  # 64 KiB
_DOT_DIR_SKIP = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "__pycache__"})


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """One file's record in the manifest."""

    path: str  # POSIX-style relative path
    sha256: str  # hex digest
    size: int  # bytes
    mtime: float  # POSIX timestamp


@dataclass(frozen=True, slots=True)
class ManifestDiff:
    """Difference between two manifests."""

    added: list[str]
    modified: list[str]
    removed: list[str]


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_HASH_BUF):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root: Path) -> list[ManifestEntry]:
    """Walk ``root`` and return one ``ManifestEntry`` per regular file.

    Skips dotted directories like ``.git`` and known noise dirs like
    ``node_modules``. Hashes are SHA-256; paths are stored POSIX-style
    relative to ``root``.
    """
    entries: list[ManifestEntry] = []
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in _DOT_DIR_SKIP for part in path.relative_to(root).parts):
            continue
        rel = path.relative_to(root).as_posix()
        stat = path.stat()
        entries.append(
            ManifestEntry(
                path=rel,
                sha256=_hash_file(path),
                size=stat.st_size,
                mtime=stat.st_mtime,
            )
        )
    return entries


def write_manifest(target: Path, entries: Iterable[ManifestEntry]) -> None:
    """Write ``entries`` as JSON Lines to ``target`` atomically."""
    tmp = target.with_suffix(target.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(asdict(entry), separators=(",", ":")))
            f.write("\n")
    tmp.replace(target)


def read_manifest(target: Path) -> list[ManifestEntry]:
    """Parse a manifest written by :func:`write_manifest`."""
    out: list[ManifestEntry] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        out.append(ManifestEntry(**json.loads(line)))
    return out


def diff_manifests(old: list[ManifestEntry], new: list[ManifestEntry]) -> ManifestDiff:
    """Compute ``added`` / ``modified`` / ``removed`` paths between two manifests."""
    old_by_path = {e.path: e for e in old}
    new_by_path = {e.path: e for e in new}
    added = sorted(set(new_by_path) - set(old_by_path))
    removed = sorted(set(old_by_path) - set(new_by_path))
    modified = sorted(
        path
        for path in set(old_by_path) & set(new_by_path)
        if old_by_path[path].sha256 != new_by_path[path].sha256
    )
    return ManifestDiff(added=added, modified=modified, removed=removed)
