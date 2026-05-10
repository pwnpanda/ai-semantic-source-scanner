"""Tests for ai_codescan.engines.codeql."""

import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from ai_codescan.engines.codeql import (
    CodeqlResult,
    _write_tag_filtered_suite,
    build_database,
    ensure_query_pack,
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


def test_tag_filtered_suite_uses_go_pack(tmp_path: Path) -> None:
    suite = tmp_path / "filter.qls"
    _write_tag_filtered_suite(suite, ["security/cwe/cwe-089"], language="go")
    instructions = yaml.safe_load(suite.read_text(encoding="utf-8"))
    queries_step = next(step for step in instructions if "queries" in step)
    assert queries_step["from"] == "codeql/go-queries"


def test_tag_filtered_suite_uses_ruby_pack(tmp_path: Path) -> None:
    suite = tmp_path / "filter.qls"
    _write_tag_filtered_suite(suite, ["security/cwe/cwe-089"], language="ruby")
    instructions = yaml.safe_load(suite.read_text(encoding="utf-8"))
    queries_step = next(step for step in instructions if "queries" in step)
    assert queries_step["from"] == "codeql/ruby-queries"


def test_tag_filtered_suite_uses_csharp_pack(tmp_path: Path) -> None:
    suite = tmp_path / "filter.qls"
    _write_tag_filtered_suite(suite, ["security/cwe/cwe-089"], language="csharp")
    instructions = yaml.safe_load(suite.read_text(encoding="utf-8"))
    queries_step = next(step for step in instructions if "queries" in step)
    assert queries_step["from"] == "codeql/csharp-queries"


def test_tag_filtered_suite_rejects_unknown_language(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported codeql language"):
        _write_tag_filtered_suite(tmp_path / "f.qls", ["x"], language="cobol")


# ---------------------------------------------------------------------------
# ensure_query_pack: pack download with retry + timeout
# ---------------------------------------------------------------------------


def test_ensure_query_pack_rejects_unknown_language() -> None:
    with pytest.raises(ValueError, match="unsupported codeql language"):
        ensure_query_pack("cobol")


def test_ensure_query_pack_noop_when_codeql_missing() -> None:
    """Without ``codeql`` on PATH the helper silently returns — the
    caller surfaces a clearer error elsewhere."""
    with patch("ai_codescan.engines.codeql.shutil.which", return_value=None):
        ensure_query_pack("python")  # must not raise


def test_ensure_query_pack_succeeds_on_first_attempt() -> None:
    """Happy path: a single subprocess.run call, no retries."""
    with (
        patch(
            "ai_codescan.engines.codeql.shutil.which",
            return_value="/usr/local/bin/codeql",
        ),
        patch("ai_codescan.engines.codeql.subprocess.run") as mock_run,
    ):
        ensure_query_pack("python")
    assert mock_run.call_count == 1
    call_argv = mock_run.call_args.args[0]
    assert call_argv == ["codeql", "pack", "download", "codeql/python-queries"]


def test_ensure_query_pack_retries_on_failure_then_succeeds() -> None:
    """A transient CalledProcessError on the first attempt is retried."""
    with (
        patch(
            "ai_codescan.engines.codeql.shutil.which",
            return_value="/usr/local/bin/codeql",
        ),
        patch("ai_codescan.engines.codeql.subprocess.run") as mock_run,
    ):
        mock_run.side_effect = [
            subprocess.CalledProcessError(1, ["codeql"], stderr=b"transient"),
            None,  # second attempt succeeds
        ]
        ensure_query_pack("ruby")
    assert mock_run.call_count == 2


def test_ensure_query_pack_raises_after_exhausting_retries() -> None:
    """All attempts fail → final RuntimeError surfaces with pack name."""
    with (
        patch(
            "ai_codescan.engines.codeql.shutil.which",
            return_value="/usr/local/bin/codeql",
        ),
        patch("ai_codescan.engines.codeql.subprocess.run") as mock_run,
    ):
        mock_run.side_effect = subprocess.TimeoutExpired(["codeql"], timeout=1)
        with pytest.raises(RuntimeError, match=r"codeql/java-queries"):
            ensure_query_pack("java")
    # 1 initial attempt + 2 retries.
    assert mock_run.call_count == 3


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


# ---------------------------------------------------------------------------
# Real CodeQL integration tests for the other supported languages
# ---------------------------------------------------------------------------
#
# Each fixture-based test runs the full ``codeql database create`` +
# ``codeql database analyze`` flow against a tiny-* fixture. They are
# gated on the CodeQL CLI being installed (the language pack is fetched
# on first run if missing) plus any host-toolchain prerequisites the
# extractor needs:
#
#   - Java / C#: ``--build-mode=none`` — no host toolchain required.
#   - Ruby: bare-source extraction — no host toolchain required.
#   - Go: autobuild needs the ``go`` toolchain on PATH.


def _has_go_toolchain() -> bool:
    return shutil.which("go") is not None


@pytest.mark.integration
@pytest.mark.skipif(not _has_codeql(), reason="codeql cli not installed")
def test_codeql_runs_against_tiny_spring_java(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build + analyze tiny-spring with the Java extractor (build-mode=none)."""
    try:
        ensure_query_pack("java")
    except RuntimeError as exc:
        pytest.skip(f"codeql/java-queries pack unavailable: {exc}")
    cache = tmp_path / "cache"
    cache.mkdir()
    db_path = build_database(
        fixtures_dir / "tiny-spring",
        cache_dir=cache,
        project_id="tiny-spring",
        language="java",
    )
    assert db_path.is_dir()
    result = run_queries(
        db_path,
        cache_dir=cache,
        project_id="tiny-spring",
        codeql_tags=["security/cwe/cwe-089"],
        language="java",
    )
    assert result.sarif_path.is_file()
    assert result.sarif_path.stat().st_size > 0


@pytest.mark.integration
@pytest.mark.skipif(not _has_codeql(), reason="codeql cli not installed")
@pytest.mark.skipif(not _has_go_toolchain(), reason="go toolchain not installed")
def test_codeql_runs_against_tiny_gin_go(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build + analyze tiny-gin with the Go extractor (autobuild)."""
    try:
        ensure_query_pack("go")
    except RuntimeError as exc:
        pytest.skip(f"codeql/go-queries pack unavailable: {exc}")
    cache = tmp_path / "cache"
    cache.mkdir()
    db_path = build_database(
        fixtures_dir / "tiny-gin",
        cache_dir=cache,
        project_id="tiny-gin",
        language="go",
    )
    assert db_path.is_dir()
    result = run_queries(
        db_path,
        cache_dir=cache,
        project_id="tiny-gin",
        codeql_tags=["security/cwe/cwe-089"],
        language="go",
    )
    assert result.sarif_path.is_file()
    assert result.sarif_path.stat().st_size > 0


@pytest.mark.integration
@pytest.mark.skipif(not _has_codeql(), reason="codeql cli not installed")
def test_codeql_runs_against_tiny_sinatra_ruby(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build + analyze tiny-sinatra with the Ruby extractor (bare-source)."""
    try:
        ensure_query_pack("ruby")
    except RuntimeError as exc:
        pytest.skip(f"codeql/ruby-queries pack unavailable: {exc}")
    cache = tmp_path / "cache"
    cache.mkdir()
    db_path = build_database(
        fixtures_dir / "tiny-sinatra",
        cache_dir=cache,
        project_id="tiny-sinatra",
        language="ruby",
    )
    assert db_path.is_dir()
    result = run_queries(
        db_path,
        cache_dir=cache,
        project_id="tiny-sinatra",
        codeql_tags=["security/cwe/cwe-089"],
        language="ruby",
    )
    assert result.sarif_path.is_file()
    assert result.sarif_path.stat().st_size > 0


@pytest.mark.integration
@pytest.mark.skipif(not _has_codeql(), reason="codeql cli not installed")
def test_codeql_runs_against_tiny_aspnet_csharp(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build + analyze tiny-aspnet with the C# extractor (build-mode=none)."""
    try:
        ensure_query_pack("csharp")
    except RuntimeError as exc:
        pytest.skip(f"codeql/csharp-queries pack unavailable: {exc}")
    cache = tmp_path / "cache"
    cache.mkdir()
    db_path = build_database(
        fixtures_dir / "tiny-aspnet",
        cache_dir=cache,
        project_id="tiny-aspnet",
        language="csharp",
    )
    assert db_path.is_dir()
    result = run_queries(
        db_path,
        cache_dir=cache,
        project_id="tiny-aspnet",
        codeql_tags=["security/cwe/cwe-089"],
        language="csharp",
    )
    assert result.sarif_path.is_file()
    assert result.sarif_path.stat().st_size > 0
