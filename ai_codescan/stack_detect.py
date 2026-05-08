"""Detect logical projects (each with one ``package.json``) inside a snapshot.

Phase 1A only handles JS/TS + HTML targets; framework fingerprinting lives
in Task 7. This module is responsible for enumerating projects and labeling
their language and workspace topology.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

_SKIP_DIRS = frozenset({"node_modules", ".git", ".pnpm", ".yarn", "dist", "build", ".next"})


class ProjectKind(StrEnum):
    """Coarse classification of a detected project."""

    NODE = "node"  # has a package.json
    HTML_ONLY = "html"  # no package.json, but contains HTML


@dataclass(frozen=True, slots=True)
class Project:
    """One logical project inside a snapshot."""

    name: str
    kind: ProjectKind
    base_path: Path  # relative to snapshot root, "." for root
    languages: set[str] = field(default_factory=set)
    has_tsconfig: bool = False
    is_workspace_member: bool = False
    workspace_root: Path | None = None  # base_path of the workspace root (if any)
    frameworks: set[str] = field(default_factory=set)
    package_manager: str = "unknown"


def _is_workspace_root(pkg_json: Path) -> bool:
    """Return True if this package.json declares pnpm/yarn/npm workspaces."""
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if "workspaces" in data:
        return True
    return (pkg_json.parent / "pnpm-workspace.yaml").is_file()


def _iter_files(root: Path, suffix: str) -> Iterator[Path]:
    for path in root.rglob(f"*{suffix}"):
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def _detect_languages(pkg_dir: Path) -> set[str]:
    languages: set[str] = set()
    for ext, lang in (
        (".js", "javascript"),
        (".jsx", "javascript"),
        (".mjs", "javascript"),
        (".cjs", "javascript"),
        (".ts", "typescript"),
        (".tsx", "typescript"),
        (".html", "html"),
        (".htm", "html"),
        (".vue", "vue"),
        (".svelte", "svelte"),
    ):
        if any(_iter_files(pkg_dir, ext)):
            languages.add(lang)
    return languages


def _project_name(pkg_json: Path) -> str:
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return pkg_json.parent.name
    return str(data.get("name") or pkg_json.parent.name)


_FRAMEWORK_DEPS: dict[str, str] = {
    # dependency-name → framework label
    "express": "express",
    "fastify": "fastify",
    "@nestjs/core": "nest",
    "next": "nextjs",
    "react": "react",
    "react-dom": "react",
    "vue": "vue",
    "@vue/runtime-core": "vue",
    "svelte": "svelte",
    "@sveltejs/kit": "sveltekit",
    "@angular/core": "angular",
    "astro": "astro",
    "koa": "koa",
    "hapi": "hapi",
    "@hapi/hapi": "hapi",
    "remix": "remix",
    "@remix-run/server-runtime": "remix",
}


def _detect_frameworks(pkg_json: Path) -> set[str]:
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps.update(data.get(key) or {})
    return {label for dep, label in _FRAMEWORK_DEPS.items() if dep in deps}


def _detect_package_manager(workspace_root: Path) -> str:
    if (workspace_root / "pnpm-lock.yaml").is_file():
        return "pnpm"
    if (workspace_root / "yarn.lock").is_file():
        return "yarn"
    if (workspace_root / "bun.lock").is_file() or (workspace_root / "bun.lockb").is_file():
        return "bun"
    if (workspace_root / "package-lock.json").is_file():
        return "npm"
    if (workspace_root / "npm-shrinkwrap.json").is_file():
        return "npm"
    return "unknown"


def detect_projects(root: Path) -> list[Project]:
    """Return all projects discovered under ``root``."""
    pkg_jsons = sorted(
        p
        for p in root.rglob("package.json")
        if not any(part in _SKIP_DIRS for part in p.relative_to(root).parts)
    )

    workspace_root_path: Path | None = None
    for pkg in pkg_jsons:
        rel = pkg.parent.relative_to(root)
        if rel == Path(".") and _is_workspace_root(pkg):
            workspace_root_path = rel
            break

    projects: list[Project] = []
    for pkg in pkg_jsons:
        rel = pkg.parent.relative_to(root)
        is_root = rel == Path(".")
        if is_root and workspace_root_path is not None:
            continue
        pm_root = root / (workspace_root_path or Path("."))
        package_manager = _detect_package_manager(pm_root)
        projects.append(
            Project(
                name=_project_name(pkg),
                kind=ProjectKind.NODE,
                base_path=rel,
                languages=_detect_languages(pkg.parent),
                has_tsconfig=(pkg.parent / "tsconfig.json").is_file(),
                is_workspace_member=workspace_root_path is not None and not is_root,
                workspace_root=workspace_root_path,
                frameworks=_detect_frameworks(pkg),
                package_manager=package_manager,
            )
        )

    if not projects and (any(_iter_files(root, ".html")) or any(_iter_files(root, ".htm"))):
        projects.append(
            Project(
                name=root.name,
                kind=ProjectKind.HTML_ONLY,
                base_path=Path("."),
                languages={"html"},
            )
        )
    return projects
