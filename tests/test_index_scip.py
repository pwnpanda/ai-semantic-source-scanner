"""Tests for ai_codescan.index.scip."""

import shutil
import subprocess
from pathlib import Path

import pytest

from ai_codescan.index.scip import (
    IndexResult,
    ScipDependenciesUnavailableError,
    ScipWorkspace,
    build_scip_index,
    isolated_node_dependency_workspace,
)
from ai_codescan.third_party import scip_pb2


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
    payload = scip_pb2.Index(
        documents=[scip_pb2.Document(relative_path="src/App.kt")]
    ).SerializeToString()
    prebuilt.write_bytes(payload)
    monkeypatch.setenv("AI_CODESCAN_SCIP_JAVA_INDEX", str(prebuilt))
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    result = build_scip_index(project, cache_dir=cache, project_id="j", language="java")

    assert result.scip_path.read_bytes() == payload


def test_build_scip_java_rejects_missing_prebuilt_index(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "j"
    project.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    missing = tmp_path / "missing.scip"
    monkeypatch.setenv("AI_CODESCAN_SCIP_JAVA_INDEX", str(missing))

    with pytest.raises(RuntimeError, match="does not point to a file"):
        build_scip_index(project, cache_dir=cache, project_id="j", language="java")


def test_build_scip_java_rejects_malformed_prebuilt_index(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "j"
    project.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    prebuilt = tmp_path / "malformed.scip"
    prebuilt.write_bytes(b"not-a-protobuf")
    monkeypatch.setenv("AI_CODESCAN_SCIP_JAVA_INDEX", str(prebuilt))

    with pytest.raises(RuntimeError, match=r"malformed\.scip.*regenerate.*unset"):
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


def test_build_scip_typescript_infers_config_in_writable_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "snapshot" / "packages" / "helpers"
    project.mkdir(parents=True)
    source = project / "helper.ts"
    source.write_text("export const helper = true;\n", encoding="utf-8")
    source.chmod(0o444)
    project.chmod(0o555)
    cache = tmp_path / "cache"
    workspaces: list[Path] = []

    def fake_run(argv, *, cwd, check, capture_output):
        assert check is True
        assert capture_output is True
        workspace = Path(cwd)
        workspaces.append(workspace)
        assert workspace != project
        assert workspace.stat().st_mode & 0o200
        (workspace / "tsconfig.json").write_text("{}\n", encoding="utf-8")
        Path(argv[argv.index("--output") + 1]).write_bytes(b"scip-index")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/scip-typescript")
    monkeypatch.setattr("ai_codescan.index.scip.subprocess.run", fake_run)

    result = build_scip_index(
        project,
        cache_dir=cache,
        project_id="helpers",
        language="javascript",
        workspace=ScipWorkspace(
            snapshot_root=tmp_path / "snapshot",
            project_base_path=Path("packages/helpers"),
            dependency_root=tmp_path / "target",
        ),
    )
    project.chmod(0o755)
    source.chmod(0o644)

    assert result.scip_path.read_bytes() == b"scip-index"
    assert not (project / "tsconfig.json").exists()
    assert workspaces and not workspaces[0].exists()


def test_build_scip_typescript_links_workspace_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "snapshot" / "apps" / "mobile"
    project.mkdir(parents=True)
    (tmp_path / "snapshot" / "tsconfig.json").write_text("{}\n", encoding="utf-8")
    (project / "App.tsx").write_text("export const App = () => null;\n", encoding="utf-8")
    (project / "tsconfig.json").write_text(
        '{"extends":"expo/tsconfig.base"}\n',
        encoding="utf-8",
    )
    target = tmp_path / "target"
    expo = target / "node_modules" / "expo"
    expo.mkdir(parents=True)
    (expo / "package.json").write_text('{"name":"expo"}\n', encoding="utf-8")
    (expo / "tsconfig.base.json").write_text("{}\n", encoding="utf-8")
    cache = tmp_path / "cache"

    def fake_run(argv, *, cwd, check, capture_output):
        assert check is True
        assert capture_output is True
        workspace = Path(cwd)
        assert (workspace.parents[1] / "tsconfig.json").is_file()
        linked_expo = workspace.parents[1] / "node_modules" / "expo"
        assert linked_expo.resolve() == expo.resolve()
        Path(argv[argv.index("--output") + 1]).write_bytes(b"scip-index")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/scip-typescript")
    monkeypatch.setattr("ai_codescan.index.scip.subprocess.run", fake_run)

    result = build_scip_index(
        project,
        cache_dir=cache,
        project_id="mobile-app",
        language="javascript",
        workspace=ScipWorkspace(
            snapshot_root=tmp_path / "snapshot",
            project_base_path=Path("apps/mobile"),
            dependency_root=target,
        ),
    )

    assert result.scip_path.read_bytes() == b"scip-index"


def test_isolated_node_dependency_install_disables_scripts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "package.json").write_text('{"name":"workspace"}\n', encoding="utf-8")
    (source / "package-lock.json").write_text(
        '{"name":"workspace","lockfileVersion":3,"packages":{}}\n',
        encoding="utf-8",
    )
    installed_workspaces: list[Path] = []

    def fake_run(argv, *, cwd, check, capture_output):
        assert check is True
        assert capture_output is True
        assert argv == ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]
        workspace = Path(cwd)
        installed_workspaces.append(workspace)
        (workspace / "node_modules").mkdir()

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/npm")
    monkeypatch.setattr("ai_codescan.index.scip.subprocess.run", fake_run)

    with isolated_node_dependency_workspace(source, cache_dir=tmp_path / "cache") as workspace:
        assert workspace != source
        assert (workspace / "node_modules").is_dir()
        assert not (source / "node_modules").exists()

    assert installed_workspaces and not installed_workspaces[0].exists()


@pytest.mark.integration
@pytest.mark.skipif(not _has_scip_typescript(), reason="scip-typescript not installed")
def test_build_scip_typescript_resolves_linked_tsconfig_dependency(tmp_path: Path) -> None:
    project = tmp_path / "snapshot" / "apps" / "mobile"
    project.mkdir(parents=True)
    (project / "App.tsx").write_text("export const App = () => null;\n", encoding="utf-8")
    (project / "tsconfig.json").write_text(
        '{"extends":"expo/tsconfig.base","include":["App.tsx"]}\n',
        encoding="utf-8",
    )
    target = tmp_path / "target"
    expo = target / "node_modules" / "expo"
    expo.mkdir(parents=True)
    (expo / "package.json").write_text('{"name":"expo"}\n', encoding="utf-8")
    (expo / "tsconfig.base.json").write_text(
        '{"compilerOptions":{"jsx":"react-jsx"}}\n',
        encoding="utf-8",
    )

    result = build_scip_index(
        project,
        cache_dir=tmp_path / "cache",
        project_id="mobile-app",
        language="javascript",
        workspace=ScipWorkspace(
            snapshot_root=tmp_path / "snapshot",
            project_base_path=Path("apps/mobile"),
            dependency_root=target,
        ),
    )

    assert any(document.relative_path == "App.tsx" for document in result.iter_documents())


def test_build_scip_java_waits_for_react_native_and_expo_packages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "snapshot" / "apps" / "mobile" / "android"
    project.mkdir(parents=True)
    (project / "settings.gradle.kts").write_text(
        'includeBuild("../node_modules/@react-native/gradle-plugin")\n'
        'id("expo-autolinking-settings")\n',
        encoding="utf-8",
    )
    target = tmp_path / "target"
    cache = tmp_path / "cache"
    calls = 0

    def fake_run(argv, *, cwd, check, capture_output):
        nonlocal calls
        calls += 1
        assert check is True
        assert capture_output is True
        workspace = Path(cwd)
        modules = workspace.parent / "node_modules"
        assert (modules / "@react-native/gradle-plugin/package.json").is_file()
        assert (modules / "expo-modules-autolinking/package.json").is_file()
        Path(argv[argv.index("--output") + 1]).write_bytes(b"scip-index")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/scip-java")
    monkeypatch.setattr("ai_codescan.index.scip.subprocess.run", fake_run)
    workspace = ScipWorkspace(
        snapshot_root=tmp_path / "snapshot",
        project_base_path=Path("apps/mobile/android"),
        dependency_root=target,
    )

    with pytest.raises(ScipDependenciesUnavailableError, match="@react-native.*expo"):
        build_scip_index(
            project,
            cache_dir=cache,
            project_id="mobile-android",
            language="java",
            workspace=workspace,
        )
    assert calls == 0

    for package in ("@react-native/gradle-plugin", "expo-modules-autolinking"):
        package_dir = target / "apps" / "mobile" / "node_modules" / package
        package_dir.mkdir(parents=True)
        (package_dir / "package.json").write_text("{}\n", encoding="utf-8")

    result = build_scip_index(
        project,
        cache_dir=cache,
        project_id="mobile-android",
        language="java",
        workspace=workspace,
    )

    assert calls == 1
    assert result.scip_path.read_bytes() == b"scip-index"


def test_scip_failure_includes_stderr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "project"
    project.mkdir()

    def fake_run(argv, **_kwargs):
        raise subprocess.CalledProcessError(1, argv, stderr=b"Expo plugin is unavailable")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/scip-go")
    monkeypatch.setattr("ai_codescan.index.scip.subprocess.run", fake_run)

    with pytest.raises(RuntimeError, match="scip-go.*Expo plugin is unavailable"):
        build_scip_index(
            project,
            cache_dir=tmp_path / "cache",
            project_id="project",
            language="go",
        )


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
