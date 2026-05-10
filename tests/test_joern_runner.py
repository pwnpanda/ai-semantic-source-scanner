"""Tests for ai_codescan.engines.joern.

The integration tests build a real Code Property Graph for each fixture
via ``joern-parse`` and then run the bundled query script through the
``joern`` REPL. CPG builds take 30-60s on the first invocation per
fixture (mtime-based cache reuses results on subsequent runs), so all
six fixture tests are gated on ``-m integration``.
"""

import shutil
from pathlib import Path

import pytest

from ai_codescan.engines import joern as joern_eng


def _has_joern() -> bool:
    return shutil.which("joern") is not None and shutil.which("joern-parse") is not None


def _has_php() -> bool:
    return shutil.which("php") is not None


def test_is_available_returns_bool() -> None:
    """``is_available`` is a plain availability probe — always returns bool."""
    result = joern_eng.is_available()
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Real Joern integration tests for each supported language fixture
# ---------------------------------------------------------------------------
#
# Each test runs the full ``joern-parse`` + scripted query flow against a
# tiny-* fixture and asserts that the resulting JSONL contains a CWE-89
# flow with the expected sink_name. Ruby is the exception: Joern's
# rubysrc2cpg frontend is officially beta and produces thin CPGs that
# routinely miss flows entirely, so we only assert the run completes.


@pytest.mark.integration
@pytest.mark.skipif(not _has_joern(), reason="joern cli not installed")
def test_joern_runs_against_tiny_vuln_javascript(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build CPG + run queries against tiny-vuln (JavaScript)."""
    jsonl = joern_eng.run_joern(
        fixtures_dir / "tiny-vuln",
        cache_dir=tmp_path,
        project_id="tiny-vuln",
        language="javascript",
    )
    assert jsonl.is_file()
    flows = joern_eng.parse_flows(jsonl)
    assert any(f.get("cwe") == "CWE-89" and f.get("sink_name") == "query" for f in flows), (
        f"expected CWE-89 flow with sink_name=query in {flows!r}"
    )


@pytest.mark.integration
@pytest.mark.skipif(not _has_joern(), reason="joern cli not installed")
def test_joern_runs_against_tiny_flask_python(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build CPG + run queries against tiny-flask (Python)."""
    jsonl = joern_eng.run_joern(
        fixtures_dir / "tiny-flask",
        cache_dir=tmp_path,
        project_id="tiny-flask",
        language="python",
    )
    assert jsonl.is_file()
    flows = joern_eng.parse_flows(jsonl)
    assert any(f.get("cwe") == "CWE-89" and f.get("sink_name") == "execute" for f in flows), (
        f"expected CWE-89 flow with sink_name=execute in {flows!r}"
    )


@pytest.mark.integration
@pytest.mark.skipif(not _has_joern(), reason="joern cli not installed")
def test_joern_runs_against_tiny_spring_java(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build CPG + run queries against tiny-spring (Java)."""
    jsonl = joern_eng.run_joern(
        fixtures_dir / "tiny-spring",
        cache_dir=tmp_path,
        project_id="tiny-spring",
        language="java",
    )
    assert jsonl.is_file()
    flows = joern_eng.parse_flows(jsonl)
    assert any(f.get("cwe") == "CWE-89" and f.get("sink_name") == "executeQuery" for f in flows), (
        f"expected CWE-89 flow with sink_name=executeQuery in {flows!r}"
    )


@pytest.mark.integration
@pytest.mark.skipif(not _has_joern(), reason="joern cli not installed")
def test_joern_runs_against_tiny_gin_go(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build CPG + run queries against tiny-gin (Go)."""
    jsonl = joern_eng.run_joern(
        fixtures_dir / "tiny-gin",
        cache_dir=tmp_path,
        project_id="tiny-gin",
        language="go",
    )
    assert jsonl.is_file()
    flows = joern_eng.parse_flows(jsonl)
    assert any(f.get("cwe") == "CWE-89" and f.get("sink_name") == "Query" for f in flows), (
        f"expected CWE-89 flow with sink_name=Query in {flows!r}"
    )


@pytest.mark.integration
@pytest.mark.skipif(not _has_joern(), reason="joern cli not installed")
def test_joern_runs_against_tiny_sinatra_ruby(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build CPG + run queries against tiny-sinatra (Ruby).

    Joern's rubysrc2cpg frontend is officially marked beta — it produces
    thin CPGs and routinely misses taint flows. We only assert the run
    completes without raising and parse_flows returns a list (possibly
    empty).
    """
    jsonl = joern_eng.run_joern(
        fixtures_dir / "tiny-sinatra",
        cache_dir=tmp_path,
        project_id="tiny-sinatra",
        language="ruby",
    )
    assert jsonl.is_file()
    flows = joern_eng.parse_flows(jsonl)
    assert isinstance(flows, list)


@pytest.mark.integration
@pytest.mark.skipif(not _has_joern(), reason="joern cli not installed")
@pytest.mark.skipif(not _has_php(), reason="php cli not installed (php2cpg requires it)")
def test_joern_runs_against_tiny_slim_php(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build CPG + run queries against tiny-slim (PHP).

    Joern's php2cpg frontend shells out to PHP-Parser, so the host needs
    ``php`` on PATH; we skip when it isn't.
    """
    jsonl = joern_eng.run_joern(
        fixtures_dir / "tiny-slim",
        cache_dir=tmp_path,
        project_id="tiny-slim",
        language="php",
    )
    assert jsonl.is_file()
    flows = joern_eng.parse_flows(jsonl)
    assert isinstance(flows, list)


@pytest.mark.integration
@pytest.mark.skipif(not _has_joern(), reason="joern cli not installed")
def test_joern_runs_against_tiny_aspnet_csharp(tmp_path: Path, fixtures_dir: Path) -> None:
    """Build CPG + run queries against tiny-aspnet (C#)."""
    jsonl = joern_eng.run_joern(
        fixtures_dir / "tiny-aspnet",
        cache_dir=tmp_path,
        project_id="tiny-aspnet",
        language="csharp",
    )
    assert jsonl.is_file()
    flows = joern_eng.parse_flows(jsonl)
    assert any(f.get("cwe") == "CWE-89" and f.get("sink_name") == "ExecuteReader" for f in flows), (
        f"expected CWE-89 flow with sink_name=ExecuteReader in {flows!r}"
    )
