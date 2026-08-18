"""Tests for cached source path containment."""

from pathlib import Path

import pytest

from ai_codescan.source_paths import SourcePathError, resolve_contained_file


def test_resolve_contained_file_accepts_relative_and_snapshot_absolute_paths(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source = source_root / "src" / "App.kt"
    source.parent.mkdir(parents=True)
    source.write_text("fun main() = Unit\n", encoding="utf-8")

    assert resolve_contained_file(source_root, "src/App.kt") == source
    assert resolve_contained_file(source_root, source) == source


@pytest.mark.parametrize("value", ("/etc/passwd", "../outside.txt"))
def test_resolve_contained_file_rejects_absolute_and_traversal_escapes(
    tmp_path: Path,
    value: str,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (tmp_path / "outside.txt").write_text("outside sentinel\n", encoding="utf-8")

    with pytest.raises(SourcePathError, match="escapes snapshot"):
        resolve_contained_file(source_root, value)


def test_resolve_contained_file_rejects_symlink_escape(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside sentinel\n", encoding="utf-8")
    (source_root / "linked.kt").symlink_to(outside)

    with pytest.raises(SourcePathError, match="escapes snapshot"):
        resolve_contained_file(source_root, "linked.kt")


def test_resolve_contained_file_normalizes_malformed_path_errors(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()

    with pytest.raises(SourcePathError, match="source file does not exist"):
        resolve_contained_file(source_root, "invalid\x00path.kt")
