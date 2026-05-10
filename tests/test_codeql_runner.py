"""Tests for ai_codescan.engines.codeql."""

import shutil
import subprocess
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


def _ensure_codeql_pack(pack: str) -> bool:
    """Download a CodeQL query pack if missing; return True on success.

    The integration tests in this module rely on the language-specific
    query pack (``codeql/<lang>-queries``) being resolvable so the
    tag-filtered suite's ``from:`` reference works during ``database
    analyze``. ``codeql database create`` doesn't auto-fetch query
    packs — only the extractor packs are bundled with the CLI — so we
    invoke ``codeql pack download <pack>`` lazily on first call.

    Returns True when the pack is available locally after the call,
    False if download failed (e.g. offline environment).
    """
    if not _has_codeql():
        return False
    try:
        subprocess.run(  # noqa: S603, S607 - argv-only, no shell
            ["codeql", "pack", "download", pack],
            check=True,
            capture_output=True,
            timeout=300,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False
    return True


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
    if not _ensure_codeql_pack("codeql/java-queries"):
        pytest.skip("codeql/java-queries pack unavailable (offline?)")
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
    if not _ensure_codeql_pack("codeql/go-queries"):
        pytest.skip("codeql/go-queries pack unavailable (offline?)")
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
    if not _ensure_codeql_pack("codeql/ruby-queries"):
        pytest.skip("codeql/ruby-queries pack unavailable (offline?)")
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
    if not _ensure_codeql_pack("codeql/csharp-queries"):
        pytest.skip("codeql/csharp-queries pack unavailable (offline?)")
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
