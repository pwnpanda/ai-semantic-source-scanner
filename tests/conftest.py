"""Shared pytest fixtures."""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Force a wide terminal for the whole session. typer / click format their
# ``--help`` output against ``$COLUMNS`` (or the TTY width when no env var
# is set); GitHub Actions runners have no TTY and default to a narrow
# width, which truncates option names like ``--port`` to ``-…`` and breaks
# tests that assert the full text appears in ``--help`` output. Setting
# this once in conftest keeps all CLI help tests width-invariant.
os.environ.setdefault("COLUMNS", "200")


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
