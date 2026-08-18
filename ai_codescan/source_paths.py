"""Canonical containment checks for cached source paths."""

from __future__ import annotations

from pathlib import Path


class SourcePathError(RuntimeError):
    """Raised when a scanner-supplied path escapes its allowed root."""


def _resolve_existing(path: Path, *, missing_message: str) -> Path:
    try:
        return path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SourcePathError(missing_message) from exc


def _candidate_path(value: str | Path, *, base: Path) -> Path:
    try:
        candidate = Path(value).expanduser()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise SourcePathError(f"source file does not exist: {value}") from exc
    return candidate if candidate.is_absolute() else base / candidate


def resolve_contained_file(
    root: Path,
    value: str | Path,
    *,
    relative_to: Path | None = None,
) -> Path:
    """Return an existing regular file canonically contained by ``root``.

    Relative paths are interpreted from ``relative_to`` when provided and
    from ``root`` otherwise. Resolving both the root and candidate before the
    containment check rejects ``..`` traversal and symlinks that point out of
    the allowed tree.

    Args:
        root: Directory that must contain the resolved file.
        value: Scanner- or model-supplied file path.
        relative_to: Optional in-tree base for relative paths.

    Raises:
        SourcePathError: If the root/base is invalid, the file is missing, or
            its canonical path is outside ``root``.
    """
    resolved_root = _resolve_existing(
        root,
        missing_message=f"source root does not exist: {root}",
    )
    if not resolved_root.is_dir():
        raise SourcePathError(f"source root is not a directory: {resolved_root}")

    base = resolved_root
    if relative_to is not None:
        base = _resolve_existing(
            relative_to,
            missing_message=f"relative path base does not exist: {relative_to}",
        )
        if not base.is_dir() or not base.is_relative_to(resolved_root):
            raise SourcePathError(f"relative path base escapes source root: {relative_to}")

    candidate = _candidate_path(value, base=base)
    resolved = _resolve_existing(
        candidate,
        missing_message=f"source file does not exist: {value}",
    )
    if not resolved.is_relative_to(resolved_root):
        raise SourcePathError(f"source file escapes snapshot: {value}")
    if not resolved.is_file():
        raise SourcePathError(f"source path is not a regular file: {value}")
    return resolved
