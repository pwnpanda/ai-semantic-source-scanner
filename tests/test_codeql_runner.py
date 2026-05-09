"""Tests for ai_codescan.engines.codeql."""

import shutil
from pathlib import Path

import pytest

from ai_codescan.engines.codeql import CodeqlResult, build_database, run_queries


def _has_codeql() -> bool:
    return shutil.which("codeql") is not None


@pytest.mark.integration
@pytest.mark.skipif(not _has_codeql(), reason="codeql cli not installed")
def test_build_database_succeeds_for_js_project(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    db_path = build_database(
        fixtures_dir / "tiny-vuln",
        cache_dir=cache,
        project_id="tiny-vuln",
    )
    assert db_path.is_dir()
    assert (db_path / "codeql-database.yml").is_file()


@pytest.mark.integration
@pytest.mark.skipif(not _has_codeql(), reason="codeql cli not installed")
def test_run_queries_emits_sarif(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    db_path = build_database(
        fixtures_dir / "tiny-vuln",
        cache_dir=cache,
        project_id="tiny-vuln",
    )
    result = run_queries(
        db_path,
        cache_dir=cache,
        project_id="tiny-vuln",
        codeql_tags=["security/cwe/cwe-089"],
    )
    assert isinstance(result, CodeqlResult)
    assert result.sarif_path.is_file()
    assert result.sarif_path.stat().st_size > 0
