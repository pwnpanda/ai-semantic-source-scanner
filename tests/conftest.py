"""Shared pytest fixtures."""

from __future__ import annotations

import os
import shutil

# typer / click / rich determine ``--help`` rendering width from (in
# order) ``$COLUMNS``, the TTY size, then a hard-coded 80-col fallback.
# Hosted CI runners have no TTY and inconsistent ``$COLUMNS`` handling
# across pytest plugins (some import-time plugins read width before our
# ``conftest`` runs), so set the env vars **and** monkey-patch
# ``shutil.get_terminal_size`` before any other test module imports
# typer/rich. This makes ``--help`` output width-invariant in every
# environment.
os.environ["COLUMNS"] = "200"
os.environ["LINES"] = "50"
os.environ.setdefault("TERM", "xterm-256color")
_FORCED_SIZE = os.terminal_size((200, 50))
shutil.get_terminal_size = lambda fallback=(200, 50): _FORCED_SIZE  # type: ignore[assignment]

import re  # noqa: E402 - intentional ordering
from collections.abc import Iterator  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

FIXTURES_DIR = Path(__file__).parent / "fixtures"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences so help-text assertions stay readable."""
    return _ANSI_RE.sub("", text)


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to bundled test fixture repos."""
    return FIXTURES_DIR


@pytest.fixture
def tmp_cache_dir(tmp_path: Path) -> Iterator[Path]:
    """Isolated cache directory for one test."""
    cache = tmp_path / "cache"
    cache.mkdir()
    yield cache
