"""Render the human-and-LLM-readable ``repo.md`` summary."""

from __future__ import annotations

from collections.abc import Iterable

from ai_codescan.stack_detect import Project


def _list_or_dash(items: Iterable[str]) -> str:
    sorted_items = sorted(items)
    return ", ".join(sorted_items) if sorted_items else "—"


def _render_project(project: Project) -> str:
    return "\n".join(
        [
            f"## Project: {project.name}",
            "",
            f"- Path: `{project.base_path.as_posix()}`",
            f"- Kind: {project.kind.value}",
            f"- Languages: {_list_or_dash(project.languages)}",
            f"- Frameworks: {_list_or_dash(project.frameworks)}",
            f"- Package manager: {project.package_manager}",
            f"- TS config: {'yes' if project.has_tsconfig else 'no'}",
            f"- Workspace member: {'yes' if project.is_workspace_member else 'no'}",
        ]
    )


def render_repo_md(*, target_name: str, projects: list[Project]) -> str:
    """Render ``repo.md`` content for ``target_name`` given detected ``projects``.

    Output is sorted by ``base_path`` to make reruns byte-stable.
    """
    lines = [f"# Repository: {target_name}", ""]
    if not projects:
        lines.append("No projects detected.")
        lines.append("")
        return "\n".join(lines)
    sorted_projects = sorted(projects, key=lambda p: p.base_path.as_posix())
    for project in sorted_projects:
        lines.append(_render_project(project))
        lines.append("")
    return "\n".join(lines)
