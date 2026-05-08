"""Tests for ai_codescan.index.scip."""

import shutil
from pathlib import Path

import pytest

from ai_codescan.index.scip import IndexResult, build_scip_index


def _has_scip_typescript() -> bool:
    return shutil.which("scip-typescript") is not None


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

    result = build_scip_index(project, cache_dir=cache, project_id="p")

    assert isinstance(result, IndexResult)
    assert result.scip_path.is_file()
    assert result.scip_path.stat().st_size > 0
    documents = list(result.iter_documents())
    assert any(doc.relative_path.endswith("x.ts") for doc in documents)
