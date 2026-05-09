"""Persistent user-level configuration for ai-codescan.

Stored at ``$XDG_CONFIG_HOME/ai-codescan/config.yaml`` (defaults to
``~/.config/ai-codescan/config.yaml``). Currently holds:

- ``container_runtime`` — ``"docker" | "podman" | "none"`` chosen at install time
  and reused by the validator sandbox.
- ``poc_language_preference`` — ``"auto" | "python" | …`` ; auto picks the
  target's primary language with python as a fallback.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

_VALID_RUNTIMES: tuple[str, ...] = ("docker", "podman", "none")
_VALID_PREFS: tuple[str, ...] = ("auto", "python", "javascript", "typescript", "php", "ruby", "go")


def _config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "ai-codescan"


def config_path() -> Path:
    """Return the resolved config file path (may not exist yet)."""
    return _config_dir() / "config.yaml"


@dataclass(frozen=True, slots=True)
class UserConfig:
    """Snapshot of user-level settings."""

    container_runtime: str = "docker"
    poc_language_preference: str = "auto"


def load() -> UserConfig:
    """Load config from disk; return defaults if absent.

    The ``AICS_CONTAINER_RUNTIME`` and ``AICS_POC_LANG`` environment variables
    override the on-disk values when set.
    """
    path = config_path()
    raw: dict[str, object] = {}
    if path.is_file():
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError):
            raw = {}

    runtime = str(
        os.environ.get("AICS_CONTAINER_RUNTIME") or raw.get("container_runtime") or "docker"
    )
    pref = str(os.environ.get("AICS_POC_LANG") or raw.get("poc_language_preference") or "auto")

    if runtime not in _VALID_RUNTIMES:
        runtime = "docker"
    if pref not in _VALID_PREFS:
        pref = "auto"
    return UserConfig(container_runtime=runtime, poc_language_preference=pref)


def save(cfg: UserConfig) -> Path:
    """Persist ``cfg`` to disk and return the file path."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "container_runtime": cfg.container_runtime,
        "poc_language_preference": cfg.poc_language_preference,
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    return path
