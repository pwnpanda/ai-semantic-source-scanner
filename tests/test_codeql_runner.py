"""Tests for ai_codescan.engines.codeql."""

import shutil
from pathlib import Path

import pytest
import yaml

from ai_codescan.engines.codeql import (
    CodeqlResult,
    _write_tag_filtered_suite,
    build_database,
    run_queries,
)


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


def test_tag_filtered_suite_uses_javascript_pack(tmp_path: Path) -> None:
    suite = tmp_path / "filter.qls"
    _write_tag_filtered_suite(suite, ["security/cwe/cwe-089"], language="javascript")
    instructions = yaml.safe_load(suite.read_text(encoding="utf-8"))
    queries_step = next(step for step in instructions if "queries" in step)
    assert queries_step["from"] == "codeql/javascript-queries"


def test_tag_filtered_suite_uses_python_pack(tmp_path: Path) -> None:
    suite = tmp_path / "filter.qls"
    _write_tag_filtered_suite(suite, ["security/cwe/cwe-089"], language="python")
    instructions = yaml.safe_load(suite.read_text(encoding="utf-8"))
    queries_step = next(step for step in instructions if "queries" in step)
    assert queries_step["from"] == "codeql/python-queries"


def test_tag_filtered_suite_uses_java_pack(tmp_path: Path) -> None:
    suite = tmp_path / "filter.qls"
    _write_tag_filtered_suite(suite, ["security/cwe/cwe-089"], language="java")
    instructions = yaml.safe_load(suite.read_text(encoding="utf-8"))
    queries_step = next(step for step in instructions if "queries" in step)
    assert queries_step["from"] == "codeql/java-queries"


def test_tag_filtered_suite_rejects_unknown_language(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported codeql language"):
        _write_tag_filtered_suite(tmp_path / "f.qls", ["x"], language="cobol")


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
