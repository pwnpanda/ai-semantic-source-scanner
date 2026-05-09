"""Tests for ai_codescan.index.scip."""

import shutil
from pathlib import Path

import pytest

from ai_codescan.index.scip import IndexResult, build_scip_index


def _has_scip_typescript() -> bool:
    return shutil.which("scip-typescript") is not None


def _has_scip_python() -> bool:
    return shutil.which("scip-python") is not None


def test_build_scip_index_rejects_unknown_language(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    with pytest.raises(ValueError, match="unsupported scip language"):
        build_scip_index(project, cache_dir=cache, project_id="p", language="cobol")


def test_build_scip_python_raises_when_cli_missing(tmp_path: Path, monkeypatch) -> None:
    """When ``scip-python`` is absent, the indexer surfaces a clear RuntimeError."""
    project = tmp_path / "p"
    project.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="scip-python is not on PATH"):
        build_scip_index(project, cache_dir=cache, project_id="p", language="python")


@pytest.mark.integration
@pytest.mark.skipif(not _has_scip_typescript(), reason="scip-typescript not installed")
def test_build_scip_index_writes_protobuf(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    (project / "package.json").write_text('{"name":"p"}')
    (project / "tsconfig.json").write_text('{"compilerOptions":{"target":"ES2022"}}')
    (project / "x.ts").write_text("export function f(): number { return 1; }\n")

    cache = tmp_path / "cache"
    cache.mkdir()

    result = build_scip_index(project, cache_dir=cache, project_id="p", language="javascript")

    assert isinstance(result, IndexResult)
    assert result.scip_path.is_file()
    assert result.scip_path.stat().st_size > 0
    documents = list(result.iter_documents())
    assert any(doc.relative_path.endswith("x.ts") for doc in documents)


@pytest.mark.integration
@pytest.mark.skipif(not _has_scip_python(), reason="scip-python not installed")
def test_build_scip_python_writes_protobuf(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        "[project]\nname='p'\nversion='0.1.0'\n", encoding="utf-8"
    )
    (project / "x.py").write_text("def f() -> int:\n    return 1\n", encoding="utf-8")

    cache = tmp_path / "cache"
    cache.mkdir()

    result = build_scip_index(project, cache_dir=cache, project_id="p", language="python")
    assert result.scip_path.is_file()
    assert result.scip_path.stat().st_size > 0
