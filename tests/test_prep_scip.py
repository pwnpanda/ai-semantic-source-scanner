"""Tests for SCIP behavior in prep."""

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from ai_codescan import prep as prep_mod
from ai_codescan.prep import _scip_occurrence_line_range
from ai_codescan.stack_detect import Project, ProjectKind
from ai_codescan.third_party import scip_pb2


def test_scip_occurrence_line_range_reads_typed_single_line() -> None:
    occurrence = scip_pb2.Occurrence(
        single_line_range=scip_pb2.SingleLineRange(
            line=4,
            start_character=2,
            end_character=7,
        )
    )

    assert _scip_occurrence_line_range(occurrence) == (5, 5)


def test_scip_occurrence_line_range_reads_typed_multi_line() -> None:
    occurrence = scip_pb2.Occurrence(
        multi_line_range=scip_pb2.MultiLineRange(
            start_line=4,
            start_character=2,
            end_line=8,
            end_character=7,
        )
    )

    assert _scip_occurrence_line_range(occurrence) == (5, 9)


@pytest.mark.parametrize(
    ("legacy_range", "expected"),
    [
        ([4, 2, 7], (5, 5)),
        ([4, 2, 8, 7], (5, 9)),
        ([], None),
        ([4, 2], None),
    ],
)
def test_scip_occurrence_line_range_reads_legacy_ranges(
    legacy_range: list[int],
    expected: tuple[int, int] | None,
) -> None:
    occurrence = scip_pb2.Occurrence(range=legacy_range)

    assert _scip_occurrence_line_range(occurrence) == expected


@pytest.mark.parametrize("plugin_id", ["com.android.application", "com.android.library"])
def test_prep_skips_android_gradle_projects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    plugin_id: str,
) -> None:
    snapshot_root = tmp_path / "snapshot"
    project_root = snapshot_root / "apps" / "mobile" / "android"
    app_root = project_root / "app"
    app_root.mkdir(parents=True)
    (app_root / "build.gradle.kts").write_text(
        f'plugins {{ id("{plugin_id}") }}\n',
        encoding="utf-8",
    )
    dependency_root = tmp_path / "target"
    project = Project(
        name="mobile-android",
        kind=ProjectKind.JAVA,
        base_path=Path("apps/mobile/android"),
        languages={"kotlin"},
    )

    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Android Gradle projects must not invoke scip-java")

    monkeypatch.setattr(prep_mod, "_scip_tool_is_available", lambda _language: True)
    monkeypatch.setattr(prep_mod, "build_scip_index", fail_if_called)

    with caplog.at_level(logging.INFO):
        lookup, had_failures = prep_mod._build_scip_lookup(
            snapshot_root,
            [project],
            tmp_path / "cache",
            dependency_root,
        )

    assert lookup == {}
    assert had_failures is False
    assert "Android Gradle application and library modules are not supported" in caplog.text


@pytest.mark.parametrize(
    ("configuration_name", "configuration"),
    [
        ("build.gradle.kts", 'plugins { kotlin("jvm") version "2.1.20" }\n'),
        ("gradle.properties", "kotlin.version=2.1.20\n"),
        (
            "build.gradle",
            'classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:2.3.0"\n',
        ),
    ],
)
def test_prep_skips_scip_for_an_incompatible_kotlin_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    configuration_name: str,
    configuration: str,
) -> None:
    snapshot_root = tmp_path / "snapshot"
    project_root = snapshot_root / "service"
    project_root.mkdir(parents=True)
    (project_root / configuration_name).write_text(configuration, encoding="utf-8")
    project = Project(
        name="service",
        kind=ProjectKind.JAVA,
        base_path=Path("service"),
        languages={"kotlin"},
    )

    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        pytest.fail("An incompatible Kotlin project must not invoke scip-java")

    monkeypatch.setattr(prep_mod, "_scip_tool_is_available", lambda _language: True)
    monkeypatch.setattr(prep_mod, "build_scip_index", fail_if_called)

    with caplog.at_level(logging.INFO):
        lookup, had_failures = prep_mod._build_scip_lookup_with_dependencies(
            snapshot_root,
            [project],
            tmp_path / "cache",
            tmp_path / "target",
        )

    assert lookup == {}
    assert had_failures is False
    assert "does not match the Kotlin 2.2 compiler used by scip-java" in caplog.text


def test_prep_runs_scip_for_kotlin_2_2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot_root = tmp_path / "snapshot"
    project_root = snapshot_root / "service"
    project_root.mkdir(parents=True)
    (project_root / "build.gradle.kts").write_text(
        'plugins { kotlin("jvm") version "2.2.0" }\n',
        encoding="utf-8",
    )
    project = Project(
        name="service",
        kind=ProjectKind.JAVA,
        base_path=Path("service"),
        languages={"kotlin"},
    )
    indexed_roots: list[Path] = []

    def record_index(root: Path, **_kwargs: object) -> SimpleNamespace:
        indexed_roots.append(root)
        return SimpleNamespace(iter_documents=lambda: iter(()))

    monkeypatch.setattr(prep_mod, "_scip_tool_is_available", lambda _language: True)
    monkeypatch.setattr(prep_mod, "build_scip_index", record_index)

    lookup, had_failures = prep_mod._build_scip_lookup_with_dependencies(
        snapshot_root,
        [project],
        tmp_path / "cache",
        tmp_path / "target",
    )

    assert lookup == {}
    assert had_failures is False
    assert indexed_roots == [project_root]
