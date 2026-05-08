"""Tests for ai_codescan.stack_detect."""

from pathlib import Path

from ai_codescan.stack_detect import (
    Project,
    ProjectKind,
    detect_projects,
)


def test_single_project_express(fixtures_dir: Path) -> None:
    projects = detect_projects(fixtures_dir / "tiny-express")
    assert len(projects) == 1
    p = projects[0]
    assert isinstance(p, Project)
    assert p.kind is ProjectKind.NODE
    assert p.base_path == Path(".")
    assert p.name == "tiny-express"
    assert "javascript" in p.languages


def test_single_project_react_typescript(fixtures_dir: Path) -> None:
    projects = detect_projects(fixtures_dir / "tiny-react")
    assert len(projects) == 1
    p = projects[0]
    assert "typescript" in p.languages
    assert p.has_tsconfig is True


def test_pnpm_monorepo_detects_each_workspace(fixtures_dir: Path) -> None:
    projects = detect_projects(fixtures_dir / "monorepo-pnpm")
    base_paths = sorted(str(p.base_path) for p in projects)
    assert base_paths == ["packages/api", "packages/web"]
    api = next(p for p in projects if p.name == "api")
    web = next(p for p in projects if p.name == "web")
    assert api.is_workspace_member is True
    assert web.is_workspace_member is True
    assert api.workspace_root == Path(".")


def test_html_only_directory_yields_html_project(fixtures_dir: Path, tmp_path: Path) -> None:
    site = tmp_path / "site"
    site.mkdir()
    (site / "index.html").write_text("<!doctype html><p>hi</p>")
    projects = detect_projects(site)
    assert len(projects) == 1
    assert projects[0].kind is ProjectKind.HTML_ONLY
