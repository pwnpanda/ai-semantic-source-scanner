"""Tests for SCIP range compatibility in prep."""

from pathlib import Path

import pytest

from ai_codescan import prep as prep_mod
from ai_codescan.index.scip import ScipDependenciesUnavailableError, ScipWorkspace
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


def test_prep_defers_android_scip_until_node_packages_are_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot_root = tmp_path / "snapshot"
    project_root = snapshot_root / "apps" / "mobile" / "android"
    project_root.mkdir(parents=True)
    dependency_root = tmp_path / "target"
    project = Project(
        name="mobile-android",
        kind=ProjectKind.JAVA,
        base_path=Path("apps/mobile/android"),
        languages={"kotlin"},
    )

    def fail_for_missing_dependencies(
        root: Path,
        *,
        workspace: ScipWorkspace,
        **_kwargs: object,
    ) -> None:
        assert root == project_root
        assert workspace.snapshot_root == snapshot_root
        assert workspace.project_base_path == project.base_path
        assert workspace.dependency_root == dependency_root
        raise ScipDependenciesUnavailableError("React Native packages are unavailable")

    monkeypatch.setattr(prep_mod, "_scip_tool_is_available", lambda _language: True)
    monkeypatch.setattr(prep_mod, "build_scip_index", fail_for_missing_dependencies)

    lookup, had_failures = prep_mod._build_scip_lookup(
        snapshot_root,
        [project],
        tmp_path / "cache",
        dependency_root,
    )

    assert lookup == {}
    assert had_failures is True
