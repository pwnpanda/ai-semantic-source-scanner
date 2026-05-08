"""Tests for ai_codescan.manifest."""

import json
from pathlib import Path

from ai_codescan.manifest import (
    ManifestEntry,
    build_manifest,
    diff_manifests,
    read_manifest,
    write_manifest,
)


def test_build_manifest_hashes_each_file(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("alpha")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("beta")

    entries = build_manifest(tmp_path)
    paths = {e.path for e in entries}

    assert paths == {"a.txt", "sub/b.txt"}
    by_path = {e.path: e for e in entries}
    assert by_path["a.txt"].size == 5
    assert by_path["a.txt"].sha256 == (
        "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8"
    )


def test_build_manifest_skips_dot_dirs(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main")
    (tmp_path / "code.js").write_text("x=1")

    entries = build_manifest(tmp_path)

    assert {e.path for e in entries} == {"code.js"}


def test_build_manifest_paths_are_posix(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "foo.ts").write_text("//")

    entries = build_manifest(tmp_path)

    assert entries[0].path == "src/foo.ts"


def test_write_then_read_manifest_roundtrips(tmp_path: Path) -> None:
    (tmp_path / "x").write_text("x")
    src = tmp_path / "src"
    src.mkdir()
    (src / "y").write_text("yy")

    target = tmp_path / "manifest.jsonl"
    write_manifest(target, build_manifest(tmp_path))
    parsed = read_manifest(target)

    assert {e.path for e in parsed} == {"x", "src/y"}
    for line in target.read_text().splitlines():
        json.loads(line)  # each line is valid JSON


def test_diff_manifests_detects_added_modified_removed() -> None:
    old = [
        ManifestEntry(path="keep.js", sha256="aa", size=1, mtime=0.0),
        ManifestEntry(path="changes.ts", sha256="bb", size=2, mtime=0.0),
        ManifestEntry(path="removed.html", sha256="cc", size=3, mtime=0.0),
    ]
    new = [
        ManifestEntry(path="keep.js", sha256="aa", size=1, mtime=0.0),
        ManifestEntry(path="changes.ts", sha256="b2", size=2, mtime=0.0),
        ManifestEntry(path="added.css", sha256="dd", size=4, mtime=0.0),
    ]
    diff = diff_manifests(old, new)
    assert diff.added == ["added.css"]
    assert diff.modified == ["changes.ts"]
    assert diff.removed == ["removed.html"]
