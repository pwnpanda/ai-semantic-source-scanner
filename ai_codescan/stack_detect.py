"""Detect logical projects inside a snapshot.

Enumerates projects and labels their language(s), package manager, and
detected web frameworks. Supports JS/TS (Node), Python, Java (Maven/Gradle),
Go (modules), and HTML-only fallback.

  * Node projects: any directory with package.json.
  * Python projects: pyproject.toml / setup.py / setup.cfg / requirements.txt.
  * Java projects: pom.xml (Maven) / build.gradle / build.gradle.kts (Gradle).
  * Go projects: go.mod (single module) or go.work (multi-module workspace).
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".pnpm",
        ".yarn",
        "dist",
        "build",
        ".next",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "site-packages",
        "target",  # Maven build output
        ".gradle",  # Gradle cache
        ".idea",  # JetBrains caches
        "out",  # IntelliJ build dir
    }
)


class ProjectKind(StrEnum):
    """Coarse classification of a detected project."""

    NODE = "node"  # has a package.json
    PYTHON = "python"  # has pyproject.toml / setup.py / setup.cfg / requirements.txt
    JAVA = "java"  # has pom.xml or build.gradle(.kts)
    GO = "go"  # has go.mod (or go.work)
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


_LANG_BY_EXT: tuple[tuple[str, str], ...] = (
    (".js", "javascript"),
    (".jsx", "javascript"),
    (".mjs", "javascript"),
    (".cjs", "javascript"),
    (".ts", "typescript"),
    (".tsx", "typescript"),
    (".py", "python"),
    (".pyi", "python"),
    (".java", "java"),
    (".kt", "kotlin"),
    (".kts", "kotlin"),
    (".go", "go"),
    (".html", "html"),
    (".htm", "html"),
    (".vue", "vue"),
    (".svelte", "svelte"),
)


def _detect_languages(pkg_dir: Path) -> set[str]:
    languages: set[str] = set()
    for ext, lang in _LANG_BY_EXT:
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


_PYTHON_FRAMEWORK_DEPS: dict[str, str] = {
    "flask": "flask",
    "fastapi": "fastapi",
    "django": "django",
    "starlette": "starlette",
    "aiohttp": "aiohttp",
    "tornado": "tornado",
    "bottle": "bottle",
    "pyramid": "pyramid",
    "sanic": "sanic",
    "quart": "quart",
    "litestar": "litestar",
}

_PYTHON_MANIFESTS: tuple[str, ...] = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
)


def _python_manifest(pkg_dir: Path) -> Path | None:
    """Return the most authoritative Python manifest in ``pkg_dir``, or None."""
    for name in _PYTHON_MANIFESTS:
        candidate = pkg_dir / name
        if candidate.is_file():
            return candidate
    return None


def _project_name_python(manifest: Path) -> str:  # noqa: PLR0911 - one early-return per manifest type is the clearest expression
    """Best-effort Python project name from pyproject/setup.py/setup.cfg."""
    parent_name = manifest.parent.name or "python"
    if manifest.name == "pyproject.toml":
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return parent_name
        for key in ("project", "tool"):
            section = data.get(key) or {}
            if key == "project" and isinstance(section, dict) and section.get("name"):
                return str(section["name"])
            if key == "tool" and isinstance(section, dict):
                poetry = section.get("poetry") or {}
                if isinstance(poetry, dict) and poetry.get("name"):
                    return str(poetry["name"])
        return parent_name
    if manifest.name == "setup.cfg":
        match = re.search(
            r"(?im)^\s*name\s*=\s*([A-Za-z0-9_.\-]+)\s*$",
            manifest.read_text(encoding="utf-8", errors="replace"),
        )
        return match.group(1) if match else parent_name
    if manifest.name == "setup.py":
        match = re.search(
            r"name\s*=\s*['\"]([A-Za-z0-9_.\-]+)['\"]",
            manifest.read_text(encoding="utf-8", errors="replace"),
        )
        return match.group(1) if match else parent_name
    return parent_name


def _python_dependencies(pkg_dir: Path) -> set[str]:
    """Return the (lower-cased) declared deps for a Python project, best-effort."""
    deps: set[str] = set()
    pyproject = pkg_dir / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        project = data.get("project") or {}
        for spec in project.get("dependencies") or []:
            deps.add(_dep_name(spec))
        for group_specs in (project.get("optional-dependencies") or {}).values():
            for spec in group_specs or []:
                deps.add(_dep_name(spec))
        poetry = (data.get("tool") or {}).get("poetry") or {}
        for spec in poetry.get("dependencies") or {}:
            deps.add(_dep_name(spec))
    requirements = pkg_dir / "requirements.txt"
    if requirements.is_file():
        for line in requirements.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue
            deps.add(_dep_name(stripped))
    return {d for d in deps if d}


def _dep_name(spec: str) -> str:
    """Strip version markers/extras from a PEP 508-ish spec, return lower-cased name."""
    return re.split(r"[<>=!~;\s\[]", spec, maxsplit=1)[0].strip().lower()


def _detect_python_frameworks(pkg_dir: Path) -> set[str]:
    deps = _python_dependencies(pkg_dir)
    return {label for dep, label in _PYTHON_FRAMEWORK_DEPS.items() if dep in deps}


_JAVA_FRAMEWORK_DEPS: dict[str, str] = {
    # Substrings searched against the concatenated text of pom.xml / build.gradle*
    # so they catch both Maven XML coordinates (split across <groupId> +
    # <artifactId> elements) and Gradle's compact ``group:artifact:version`` form.
    "spring-boot-starter-web": "spring-boot",
    "spring-boot-starter-webflux": "spring-boot",
    "spring-webmvc": "spring",
    "spring-webflux": "spring",
    "quarkus-resteasy": "quarkus",
    "quarkus-resteasy-reactive": "quarkus",
    "quarkus-rest": "quarkus",
    "micronaut-http-server": "micronaut",
    "dropwizard-core": "dropwizard",
    "helidon-webserver": "helidon",
    "helidon-microprofile": "helidon",
    "ratpack-core": "ratpack",
    "javalin": "javalin",
    "play.api": "play",
    "vertx-web": "vertx",
}

_JAVA_MANIFESTS: tuple[str, ...] = (
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
)

_JAVA_PROJECT_NAME_RE = re.compile(
    r"<artifactId>\s*([A-Za-z0-9._\-]+)\s*</artifactId>",
)
_JAVA_GROUP_ID_RE = re.compile(
    r"<groupId>\s*([A-Za-z0-9._\-]+)\s*</groupId>",
)
_GRADLE_ROOT_PROJECT_NAME_RE = re.compile(
    r"""rootProject\.name\s*=\s*['"]([A-Za-z0-9._\-]+)['"]""",
)


def _java_manifest(pkg_dir: Path) -> Path | None:
    """Return the build manifest in ``pkg_dir`` (Maven preferred over Gradle), or None."""
    for name in _JAVA_MANIFESTS:
        candidate = pkg_dir / name
        if candidate.is_file():
            return candidate
    return None


def _project_name_java(manifest: Path) -> str:
    """Best-effort Java project name from pom.xml or settings.gradle*."""
    parent_name = manifest.parent.name or "java"
    if manifest.name == "pom.xml":
        text = manifest.read_text(encoding="utf-8", errors="replace")
        match = _JAVA_PROJECT_NAME_RE.search(text)
        if match:
            return match.group(1)
        return parent_name
    # Gradle: prefer ``rootProject.name`` from a sibling settings.gradle(.kts).
    for settings_name in ("settings.gradle", "settings.gradle.kts"):
        settings = manifest.parent / settings_name
        if not settings.is_file():
            continue
        match = _GRADLE_ROOT_PROJECT_NAME_RE.search(
            settings.read_text(encoding="utf-8", errors="replace")
        )
        if match:
            return match.group(1)
    return parent_name


def _detect_java_frameworks(pkg_dir: Path) -> set[str]:
    text_blobs: list[str] = []
    for name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        candidate = pkg_dir / name
        if candidate.is_file():
            text_blobs.append(candidate.read_text(encoding="utf-8", errors="replace"))
    if not text_blobs:
        return set()
    blob = "\n".join(text_blobs)
    return {label for needle, label in _JAVA_FRAMEWORK_DEPS.items() if needle in blob}


def _detect_java_package_manager(pkg_dir: Path) -> str:
    if (pkg_dir / "pom.xml").is_file():
        return "maven"
    if (pkg_dir / "build.gradle.kts").is_file():
        return "gradle-kts"
    if (pkg_dir / "build.gradle").is_file():
        return "gradle"
    return "unknown"


_GO_FRAMEWORK_DEPS: dict[str, str] = {
    # Match by Go module path substrings inside go.mod.
    "github.com/gin-gonic/gin": "gin",
    "github.com/labstack/echo": "echo",
    "github.com/go-chi/chi": "chi",
    "github.com/gofiber/fiber": "fiber",
    "github.com/beego/beego": "beego",
    "github.com/kataras/iris": "iris",
    "github.com/gorilla/mux": "gorilla-mux",
    "github.com/julienschmidt/httprouter": "httprouter",
    "github.com/labstack/echo/v4": "echo",
    "github.com/valyala/fasthttp": "fasthttp",
}

_GO_MODULE_RE = re.compile(r"^module\s+(\S+)\s*$", re.MULTILINE)


def _go_manifest(pkg_dir: Path) -> Path | None:
    """Return go.mod (single module) or go.work (workspace), preferring go.mod."""
    for name in ("go.mod", "go.work"):
        candidate = pkg_dir / name
        if candidate.is_file():
            return candidate
    return None


def _project_name_go(manifest: Path) -> str:
    """Best-effort Go module name; fall back to dir name."""
    parent_name = manifest.parent.name or "go"
    if manifest.name == "go.mod":
        match = _GO_MODULE_RE.search(manifest.read_text(encoding="utf-8", errors="replace"))
        if match:
            # ``module github.com/owner/repo`` — keep just the last segment as the name.
            return match.group(1).rsplit("/", 1)[-1]
    return parent_name


def _detect_go_frameworks(pkg_dir: Path) -> set[str]:
    go_mod = pkg_dir / "go.mod"
    if not go_mod.is_file():
        return set()
    text = go_mod.read_text(encoding="utf-8", errors="replace")
    return {label for needle, label in _GO_FRAMEWORK_DEPS.items() if needle in text}


def _detect_go_package_manager(pkg_dir: Path) -> str:
    if (pkg_dir / "go.work").is_file():
        return "go-workspace"
    if (pkg_dir / "go.mod").is_file():
        return "go-modules"
    return "unknown"


def _detect_python_package_manager(pkg_dir: Path) -> str:
    if (pkg_dir / "poetry.lock").is_file():
        return "poetry"
    if (pkg_dir / "uv.lock").is_file():
        return "uv"
    if (pkg_dir / "Pipfile.lock").is_file() or (pkg_dir / "Pipfile").is_file():
        return "pipenv"
    if (pkg_dir / "pdm.lock").is_file():
        return "pdm"
    if (pkg_dir / "requirements.txt").is_file():
        return "pip"
    return "unknown"


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


def _detect_python_projects(root: Path, claimed_dirs: set[Path]) -> list[Project]:
    """Find Python projects (one per directory containing a manifest).

    A directory is a Python project when it contains any of pyproject.toml,
    setup.py, setup.cfg, or requirements.txt — and it's not already covered
    by a Node project at the same path. We only emit the *outermost* Python
    project in a tree so nested packages don't multiply-report.
    """
    candidates: list[Path] = []
    for name in _PYTHON_MANIFESTS:
        for path in root.rglob(name):
            rel = path.relative_to(root)
            if any(part in _SKIP_DIRS for part in rel.parts):
                continue
            candidates.append(path.parent)
    candidates = sorted({c for c in candidates}, key=lambda p: len(p.parts))

    selected: list[Path] = []
    for cand in candidates:
        rel = cand.relative_to(root)
        if rel in claimed_dirs:
            continue
        if any(_is_descendant(rel, sel) for sel in selected):
            continue
        selected.append(rel)

    projects: list[Project] = []
    for rel in selected:
        pkg_dir = root / rel
        manifest = _python_manifest(pkg_dir)
        if manifest is None:
            continue
        projects.append(
            Project(
                name=_project_name_python(manifest),
                kind=ProjectKind.PYTHON,
                base_path=rel,
                languages=_detect_languages(pkg_dir),
                has_tsconfig=False,
                is_workspace_member=False,
                workspace_root=None,
                frameworks=_detect_python_frameworks(pkg_dir),
                package_manager=_detect_python_package_manager(pkg_dir),
            )
        )
    return projects


def _detect_java_projects(root: Path, claimed_dirs: set[Path]) -> list[Project]:
    """Find Java/JVM projects (one per directory containing pom.xml or build.gradle*).

    Multi-module Maven/Gradle builds nest sub-modules under the parent. We
    only emit the *outermost* manifest in a tree so a single multi-module
    build appears as one project; nested modules are skipped.
    """
    candidates: list[Path] = []
    for name in _JAVA_MANIFESTS:
        for path in root.rglob(name):
            rel = path.relative_to(root)
            if any(part in _SKIP_DIRS for part in rel.parts):
                continue
            candidates.append(path.parent)
    candidates = sorted({c for c in candidates}, key=lambda p: len(p.parts))

    selected: list[Path] = []
    for cand in candidates:
        rel = cand.relative_to(root)
        if rel in claimed_dirs:
            continue
        if any(_is_descendant(rel, sel) for sel in selected):
            continue
        selected.append(rel)

    projects: list[Project] = []
    for rel in selected:
        pkg_dir = root / rel
        manifest = _java_manifest(pkg_dir)
        if manifest is None:
            continue
        projects.append(
            Project(
                name=_project_name_java(manifest),
                kind=ProjectKind.JAVA,
                base_path=rel,
                languages=_detect_languages(pkg_dir),
                has_tsconfig=False,
                is_workspace_member=False,
                workspace_root=None,
                frameworks=_detect_java_frameworks(pkg_dir),
                package_manager=_detect_java_package_manager(pkg_dir),
            )
        )
    return projects


def _detect_go_projects(root: Path, claimed_dirs: set[Path]) -> list[Project]:
    """Find Go projects (one per directory containing go.mod or go.work).

    Multi-module Go workspaces (``go.work`` at the repo root with several
    ``use`` directives) emit one project per ``use``-listed module rather
    than collapsing to the workspace root, so each module's deps and
    framework footprint surface independently. Outside of workspaces the
    behaviour mirrors Python/Java: outermost ``go.mod`` only.
    """
    candidates: list[Path] = []
    for name in ("go.mod", "go.work"):
        for path in root.rglob(name):
            rel = path.relative_to(root)
            if any(part in _SKIP_DIRS for part in rel.parts):
                continue
            candidates.append(path.parent)
    candidates = sorted({c for c in candidates}, key=lambda p: len(p.parts))

    selected: list[Path] = []
    for cand in candidates:
        rel = cand.relative_to(root)
        if rel in claimed_dirs:
            continue
        if any(_is_descendant(rel, sel) for sel in selected):
            continue
        selected.append(rel)

    projects: list[Project] = []
    for rel in selected:
        pkg_dir = root / rel
        manifest = _go_manifest(pkg_dir)
        if manifest is None:
            continue
        projects.append(
            Project(
                name=_project_name_go(manifest),
                kind=ProjectKind.GO,
                base_path=rel,
                languages=_detect_languages(pkg_dir),
                has_tsconfig=False,
                is_workspace_member=False,
                workspace_root=None,
                frameworks=_detect_go_frameworks(pkg_dir),
                package_manager=_detect_go_package_manager(pkg_dir),
            )
        )
    return projects


def _is_descendant(rel: Path, ancestor: Path) -> bool:
    if ancestor == Path("."):
        return rel != Path(".")
    return ancestor in rel.parents


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
    claimed_dirs: set[Path] = set()
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
        claimed_dirs.add(rel)

    projects.extend(_detect_python_projects(root, claimed_dirs))
    projects.extend(_detect_java_projects(root, claimed_dirs))
    projects.extend(_detect_go_projects(root, claimed_dirs))

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
