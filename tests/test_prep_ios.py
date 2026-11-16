"""Native iOS project indexing tests."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

import duckdb
import pytest

from ai_codescan import prep as prep_mod
from ai_codescan.prep import run_prep
from ai_codescan.stack_detect import Project, ProjectKind, detect_projects


def _has_node() -> bool:
    return shutil.which("node") is not None


def test_detects_swift_and_objective_c_project(fixtures_dir: Path) -> None:
    projects = detect_projects(fixtures_dir / "tiny-ios")

    assert len(projects) == 1
    assert projects[0].kind is ProjectKind.IOS
    assert projects[0].languages == {"swift", "objective-c"}
    assert projects[0].package_manager == "swiftpm"


def test_detects_react_native_ios_subproject(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name":"mobile"}', encoding="utf-8")
    ios_root = tmp_path / "ios"
    ios_root.mkdir()
    (ios_root / "Podfile").write_text("platform :ios, '15.0'\n", encoding="utf-8")
    (ios_root / "AppDelegate.mm").write_text("@interface AppDelegate\n@end\n", encoding="utf-8")

    projects = detect_projects(tmp_path)
    ios_projects = [project for project in projects if project.kind is ProjectKind.IOS]

    assert len(ios_projects) == 1
    assert ios_projects[0].base_path == Path("ios")
    assert ios_projects[0].languages == {"objective-c"}
    assert ios_projects[0].package_manager == "cocoapods"


def test_detects_xcode_project(tmp_path: Path) -> None:
    xcode_project = tmp_path / "NativeApp.xcodeproj"
    xcode_project.mkdir()
    (xcode_project / "project.pbxproj").write_text("// project\n", encoding="utf-8")
    (tmp_path / "AppDelegate.swift").write_text("final class AppDelegate {}\n", encoding="utf-8")

    projects = detect_projects(tmp_path)

    assert len(projects) == 1
    assert projects[0].name == "NativeApp"
    assert projects[0].kind is ProjectKind.IOS
    assert projects[0].package_manager == "xcode"


@pytest.mark.skipif(not _has_node(), reason="node runtime required for AST extraction")
def test_prep_indexes_swift_and_objective_c(
    tmp_path: Path,
    fixtures_dir: Path,
) -> None:
    snapshot, db_path = run_prep(
        fixtures_dir / "tiny-ios",
        cache_root=tmp_path / "cache",
        engine="none",
        bug_classes=[],
        quiet=True,
    )

    assert snapshot.snapshot_dir.is_dir()
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        languages = {row[0] for row in conn.execute("SELECT DISTINCT lang FROM files").fetchall()}
        symbols = {row[0] for row in conn.execute("SELECT display_name FROM symbols").fetchall()}
        call_files = {
            Path(row[0]).name for row in conn.execute("SELECT file FROM xrefs").fetchall()
        }
    finally:
        conn.close()

    assert languages == {"swift", "objective-c"}
    assert {"Client", "load", "LegacyClient"}.issubset(symbols)
    assert {"Client.swift", "LegacyClient.m"}.issubset(call_files)


def test_codeql_skips_swift_when_host_is_not_macos(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    project = Project(
        name="mobile-ios",
        kind=ProjectKind.IOS,
        base_path=Path("ios"),
        languages={"swift", "objective-c"},
    )

    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Swift CodeQL must not run outside macOS")

    monkeypatch.setattr(prep_mod.sys, "platform", "linux")
    monkeypatch.setattr(prep_mod.shutil, "which", lambda _tool: "/usr/bin/codeql")
    monkeypatch.setattr(prep_mod, "_run_codeql_project", fail_if_called)

    with caplog.at_level(logging.INFO):
        had_failures = prep_mod._run_codeql_for_projects(
            tmp_path / "snapshot",
            [project],
            tmp_path / "repo",
            [],
            object(),
            strict=True,
        )

    assert had_failures is False
    assert "Swift extraction requires macOS" in caplog.text


def test_codeql_skips_objective_c_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    project = Project(
        name="legacy-ios",
        kind=ProjectKind.IOS,
        base_path=Path("ios"),
        languages={"objective-c"},
    )

    monkeypatch.setattr(prep_mod.shutil, "which", lambda _tool: "/usr/bin/codeql")
    with caplog.at_level(logging.INFO):
        had_failures = prep_mod._run_codeql_for_projects(
            tmp_path / "snapshot",
            [project],
            tmp_path / "repo",
            [],
            object(),
            strict=True,
        )

    assert had_failures is False
    assert "Objective-C is not supported" in caplog.text
