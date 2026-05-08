"""Tests for ai_codescan.repo_md."""

from pathlib import Path

from ai_codescan.repo_md import render_repo_md
from ai_codescan.stack_detect import Project, ProjectKind


def _project(**overrides: object) -> Project:
    base: dict[str, object] = {
        "name": "tiny",
        "kind": ProjectKind.NODE,
        "base_path": Path("."),
        "languages": {"typescript"},
        "has_tsconfig": True,
        "is_workspace_member": False,
        "workspace_root": None,
        "frameworks": {"react"},
        "package_manager": "pnpm",
    }
    base.update(overrides)
    return Project(**base)  # type: ignore[arg-type]


def test_render_includes_header_and_project_section() -> None:
    md = render_repo_md(target_name="my-target", projects=[_project()])
    assert md.startswith("# Repository: my-target\n")
    assert "## Project: tiny" in md
    assert "- Path: `.`" in md
    assert "- Kind: node" in md
    assert "- Languages: typescript" in md
    assert "- Frameworks: react" in md
    assert "- Package manager: pnpm" in md
    assert "- TS config: yes" in md


def test_render_is_stable_byte_for_byte() -> None:
    md1 = render_repo_md(target_name="t", projects=[_project()])
    md2 = render_repo_md(target_name="t", projects=[_project()])
    assert md1 == md2


def test_render_sorts_projects_by_base_path() -> None:
    md = render_repo_md(
        target_name="mono",
        projects=[
            _project(name="z", base_path=Path("packages/z")),
            _project(name="a", base_path=Path("packages/a")),
        ],
    )
    a_idx = md.index("## Project: a")
    z_idx = md.index("## Project: z")
    assert a_idx < z_idx


def test_render_handles_empty_projects() -> None:
    md = render_repo_md(target_name="empty", projects=[])
    assert "No projects detected" in md
