"""Deterministic filesystem-safe identifiers for per-project scan artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from os import PathLike

_HASH_LENGTH = 12
_MAX_SLUG_LENGTH = 64
_MAX_ARTIFACT_ID_LENGTH = _MAX_SLUG_LENGTH + _HASH_LENGTH + 1
_SAFE_ARTIFACT_ID = re.compile(
    rf"^[a-z0-9](?:[a-z0-9-]{{0,{_MAX_SLUG_LENGTH - 2}}}[a-z0-9])?"
    rf"-[0-9a-f]{{{_HASH_LENGTH}}}$"
)
_SAFE_PATH_SEGMENT = re.compile(
    rf"^[a-z0-9](?:[a-z0-9-]{{0,{_MAX_ARTIFACT_ID_LENGTH - 2}}}[a-z0-9])?$"
)
_UNSAFE_SLUG_RUN = re.compile(r"[^a-z0-9]+")


def _base_path_text(base_path: str | PathLike[str]) -> str:
    return str(base_path) or "."


def _readable_slug(project_name: str, base_path: str) -> str:
    label = project_name if base_path == "." else f"{project_name}-{base_path}"
    ascii_label = (
        unicodedata.normalize("NFKD", label).encode("ascii", errors="ignore").decode("ascii")
    )
    slug = _UNSAFE_SLUG_RUN.sub("-", ascii_label.lower()).strip("-")
    slug = slug[:_MAX_SLUG_LENGTH].rstrip("-")
    return slug or "project"


def project_artifact_id(project_name: str, base_path: str | PathLike[str]) -> str:
    """Build a readable, collision-controlled ID from raw project identity.

    Args:
        project_name: Original name read from the project's package manifest.
        base_path: Original project path relative to the repository snapshot.

    Returns:
        An ASCII identifier containing only lowercase letters, digits, and
        hyphens. Its suffix hashes both original inputs without normalization.
    """
    base_path_text = _base_path_text(base_path)
    identity = json.dumps(
        [project_name, base_path_text],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:_HASH_LENGTH]
    return f"{_readable_slug(project_name, base_path_text)}-{digest}"


def is_safe_artifact_id(project_id: str) -> bool:
    """Return whether ``project_id`` has the canonical safe artifact-ID shape."""
    return _SAFE_ARTIFACT_ID.fullmatch(project_id) is not None


def normalize_artifact_id(project_id: str) -> str:
    """Return a canonical ID safe for use as one filesystem path segment.

    Existing strict ASCII slugs remain stable for direct-engine compatibility.
    Any identifier containing separators, dots, whitespace, Unicode, or other
    unsafe characters receives the hashed root-project form used by discovery.
    """
    if _SAFE_PATH_SEGMENT.fullmatch(project_id) is not None:
        return project_id
    return project_artifact_id(project_id, ".")
