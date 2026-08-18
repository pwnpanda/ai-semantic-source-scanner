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


def test_build_scip_java_raises_when_cli_missing(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "j"
    project.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="scip-java is not on PATH"):
        build_scip_index(project, cache_dir=cache, project_id="j", language="java")


def test_build_scip_java_uses_prebuilt_index(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "j"
    project.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    prebuilt = tmp_path / "prebuilt.scip"
    prebuilt.write_bytes(b"prebuilt-index")
    monkeypatch.setenv("AI_CODESCAN_SCIP_JAVA_INDEX", str(prebuilt))
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    result = build_scip_index(project, cache_dir=cache, project_id="j", language="java")

    assert result.scip_path.read_bytes() == b"prebuilt-index"


def test_build_scip_java_rejects_missing_prebuilt_index(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "j"
    project.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    missing = tmp_path / "missing.scip"
    monkeypatch.setenv("AI_CODESCAN_SCIP_JAVA_INDEX", str(missing))

    with pytest.raises(RuntimeError, match="does not point to a file"):
        build_scip_index(project, cache_dir=cache, project_id="j", language="java")


def test_build_scip_java_does_not_mutate_source_snapshot(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "j"
    source_dir = project / "src"
    source_dir.mkdir(parents=True)
    source_file = source_dir / "App.kt"
    source_file.write_text("fun main() = Unit\n", encoding="utf-8")
    external_dir = tmp_path / "outside"
    external_dir.mkdir()
    (external_dir / "Outside.kt").write_text("fun outside() = Unit\n", encoding="utf-8")
    external_file = tmp_path / "Linked.kt"
    external_file.write_text("fun linked() = Unit\n", encoding="utf-8")
    (project / "linked-dir").symlink_to(external_dir, target_is_directory=True)
    (project / "linked-file.kt").symlink_to(external_file)
    for ignored_dir in ("vendor", "site-packages", "node_modules"):
        generated_dir = project / ignored_dir
        generated_dir.mkdir()
        (generated_dir / "Ignored.kt").write_text("fun ignored() = Unit\n", encoding="utf-8")
    source_file.chmod(0o444)
    source_dir.chmod(0o555)
    cache = tmp_path / "cache"
    cache.mkdir()
    workspaces: list[Path] = []

    def fake_run(argv, *, cwd, check, capture_output):
        assert check is True
        assert capture_output is True
        workspace = Path(cwd)
        workspaces.append(workspace)
        assert workspace != project
        assert (workspace / "src" / "App.kt").is_file()
        assert not (workspace / "linked-dir").exists()
        assert not (workspace / "linked-file.kt").exists()
        for ignored_dir in ("vendor", "site-packages", "node_modules"):
            assert not (workspace / ignored_dir).exists()
        generated_dir = workspace / "build" / "reports"
        generated_dir.mkdir(parents=True)
        (generated_dir / "problems-report.html").write_text("generated", encoding="utf-8")
        Path(argv[argv.index("--output") + 1]).write_bytes(b"scip-index")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/scip-java")
    monkeypatch.setattr("ai_codescan.index.scip.subprocess.run", fake_run)

    result = build_scip_index(project, cache_dir=cache, project_id="j", language="java")
    source_dir.chmod(0o755)
    source_file.chmod(0o644)

    assert result.scip_path.read_bytes() == b"scip-index"
    assert not (project / "build").exists()
    assert workspaces and not workspaces[0].exists()


def test_build_scip_go_raises_when_cli_missing(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "g"
    project.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="scip-go is not on PATH"):
        build_scip_index(project, cache_dir=cache, project_id="g", language="go")


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
