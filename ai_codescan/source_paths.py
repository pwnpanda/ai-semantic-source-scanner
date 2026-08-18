"""Canonical containment checks for cached source paths."""

from __future__ import annotations

from pathlib import Path


class SourcePathError(RuntimeError):
    """Raised when a scanner-supplied path escapes its allowed root."""


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
    try:
        resolved_root = root.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SourcePathError(f"source root does not exist: {root}") from exc
    if not resolved_root.is_dir():
        raise SourcePathError(f"source root is not a directory: {resolved_root}")

    base = resolved_root
    if relative_to is not None:
        try:
            base = relative_to.expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise SourcePathError(f"relative path base does not exist: {relative_to}") from exc
        if not base.is_dir() or not base.is_relative_to(resolved_root):
            raise SourcePathError(f"relative path base escapes source root: {relative_to}")

    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SourcePathError(f"source file does not exist: {value}") from exc
    if not resolved.is_relative_to(resolved_root):
        raise SourcePathError(f"source file escapes snapshot: {value}")
    if not resolved.is_file():
        raise SourcePathError(f"source path is not a regular file: {value}")
    return resolved
