"""Shared pytest fixtures."""

from collections.abc import Iterator
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


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
