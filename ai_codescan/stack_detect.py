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
        "bin",  # .NET build output
        "obj",  # .NET intermediate output
        ".vs",  # Visual Studio caches
    }
)


class ProjectKind(StrEnum):
    """Coarse classification of a detected project."""

    NODE = "node"  # has a package.json
    PYTHON = "python"  # has pyproject.toml / setup.py / setup.cfg / requirements.txt
    JAVA = "java"  # has pom.xml or build.gradle(.kts)
    GO = "go"  # has go.mod (or go.work)
    RUBY = "ruby"  # has Gemfile or *.gemspec
    PHP = "php"  # has composer.json, wp-config.php, or Drupal markers
    CSHARP = "csharp"  # has *.csproj, *.sln, or Directory.Build.props
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
    (".rb", "ruby"),
    (".rake", "ruby"),
    (".gemspec", "ruby"),
    (".php", "php"),
    (".phtml", "php"),
    (".cs", "csharp"),
    (".cshtml", "csharp"),
    (".razor", "csharp"),
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


_CSHARP_FRAMEWORK_DEPS: dict[str, str] = {
    # Substrings searched against ``.csproj`` / ``Directory.Packages.props``.
    "Microsoft.AspNetCore.App": "aspnetcore",
    "Microsoft.AspNetCore.Mvc": "aspnetcore-mvc",
    "Microsoft.AspNetCore.Components.WebAssembly": "blazor-wasm",
    "Microsoft.AspNetCore.Components.Web": "blazor-server",
    "Microsoft.AspNetCore.SignalR": "signalr",
    "Microsoft.Extensions.Hosting": "worker-service",
    "Microsoft.Azure.Functions.Worker": "azure-functions",
    "Microsoft.NET.Sdk.Functions": "azure-functions",
    "Grpc.AspNetCore": "grpc",
    "MassTransit": "masstransit",
    "MediatR": "mediatr",
    "Hangfire": "hangfire",
    "Quartz": "quartz",
    "Microsoft.Orleans": "orleans",
}

_CSPROJ_NAME_RE = re.compile(r"<AssemblyName>\s*([^<\s]+)\s*</AssemblyName>")
_CSPROJ_ROOT_NS_RE = re.compile(r"<RootNamespace>\s*([^<\s]+)\s*</RootNamespace>")


def _csharp_manifest(pkg_dir: Path) -> Path | None:
    """Return the most authoritative C# project marker.

    Preference: any ``*.csproj`` > ``*.sln`` > ``Directory.Build.props`` >
    ``global.json``.
    """
    for csproj in pkg_dir.glob("*.csproj"):
        if csproj.is_file():
            return csproj
    for sln in pkg_dir.glob("*.sln"):
        if sln.is_file():
            return sln
    for name in ("Directory.Build.props", "Directory.Packages.props", "global.json"):
        candidate = pkg_dir / name
        if candidate.is_file():
            return candidate
    return None


def _project_name_csharp(manifest: Path) -> str:
    """Best-effort C# project name.

    For ``*.csproj``: prefers ``<AssemblyName>``, falls back to
    ``<RootNamespace>``, then to the file stem (``Foo.csproj`` → ``Foo``).
    For ``*.sln``: file stem.
    """
    parent_name = manifest.parent.name or "csharp"
    if manifest.suffix == ".csproj":
        text = manifest.read_text(encoding="utf-8", errors="replace")
        for pattern in (_CSPROJ_NAME_RE, _CSPROJ_ROOT_NS_RE):
            match = pattern.search(text)
            if match:
                return match.group(1)
        return manifest.stem or parent_name
    if manifest.suffix == ".sln":
        return manifest.stem or parent_name
    return parent_name


def _detect_csharp_frameworks(pkg_dir: Path) -> set[str]:
    text_blobs: list[str] = []
    for csproj in pkg_dir.glob("*.csproj"):
        if csproj.is_file():
            text_blobs.append(csproj.read_text(encoding="utf-8", errors="replace"))
    for name in ("Directory.Build.props", "Directory.Packages.props"):
        candidate = pkg_dir / name
        if candidate.is_file():
            text_blobs.append(candidate.read_text(encoding="utf-8", errors="replace"))
    if not text_blobs:
        return set()
    blob = "\n".join(text_blobs)
    frameworks = {label for needle, label in _CSHARP_FRAMEWORK_DEPS.items() if needle in blob}
    # Heuristic: a Program.cs that constructs a WebApplication implies an
    # ASP.NET Core minimal-API surface even when only the framework
    # reference is present.
    program_cs = pkg_dir / "Program.cs"
    if program_cs.is_file():
        program_text = program_cs.read_text(encoding="utf-8", errors="replace")
        if "WebApplication.CreateBuilder" in program_text:
            frameworks.add("aspnetcore-minimal")
    return frameworks


def _detect_csharp_package_manager(pkg_dir: Path) -> str:
    if (pkg_dir / "packages.lock.json").is_file():
        return "nuget-locked"
    if any(pkg_dir.glob("*.csproj")) or any(pkg_dir.glob("*.sln")):
        return "nuget"
    return "unknown"


_PHP_FRAMEWORK_DEPS: dict[str, str] = {
    # Composer ``require`` package names. Search the concatenated
    # ``composer.json`` body for these substrings.
    "laravel/framework": "laravel",
    "symfony/symfony": "symfony",
    "symfony/http-kernel": "symfony",
    "symfony/http-foundation": "symfony",
    "symfony/framework-bundle": "symfony",
    "codeigniter4/framework": "codeigniter",
    "yiisoft/yii2": "yii",
    "slim/slim": "slim",
    "cakephp/cakephp": "cakephp",
    "drupal/core": "drupal",
}

_COMPOSER_REQUIRE_RE = re.compile(r'"([a-z0-9_\-]+/[a-z0-9_.\-]+)"\s*:')


def _php_manifest(pkg_dir: Path) -> Path | None:
    """Return the most authoritative PHP marker.

    Preference: ``composer.json`` > ``wp-config.php`` (WordPress) >
    ``core/lib/Drupal.php`` (Drupal). Returns None if no marker is found.
    """
    composer = pkg_dir / "composer.json"
    if composer.is_file():
        return composer
    wp_config = pkg_dir / "wp-config.php"
    if wp_config.is_file():
        return wp_config
    drupal_marker = pkg_dir / "core" / "lib" / "Drupal.php"
    if drupal_marker.is_file():
        return drupal_marker
    return None


def _project_name_php(manifest: Path) -> str:
    """Best-effort PHP project name from composer.json or directory."""
    parent_name = manifest.parent.name or "php"
    if manifest.name == "composer.json":
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return parent_name
        name = data.get("name") or ""
        if isinstance(name, str) and "/" in name:
            return name.split("/", 1)[1]
        if isinstance(name, str) and name:
            return name
    return parent_name


def _detect_php_frameworks(pkg_dir: Path) -> set[str]:
    composer = pkg_dir / "composer.json"
    frameworks: set[str] = set()
    if composer.is_file():
        text = composer.read_text(encoding="utf-8", errors="replace")
        for needle, label in _PHP_FRAMEWORK_DEPS.items():
            if needle in text:
                frameworks.add(label)
    if (pkg_dir / "wp-config.php").is_file() or (pkg_dir / "wp-config-sample.php").is_file():
        frameworks.add("wordpress")
    if (pkg_dir / "core" / "lib" / "Drupal.php").is_file():
        frameworks.add("drupal")
    return frameworks


def _detect_php_package_manager(pkg_dir: Path) -> str:
    if (pkg_dir / "composer.lock").is_file():
        return "composer"
    if (pkg_dir / "composer.json").is_file():
        return "composer"
    return "unknown"


_RUBY_FRAMEWORK_GEMS: dict[str, str] = {
    "rails": "rails",
    "sinatra": "sinatra",
    "hanami": "hanami",
    "grape": "grape",
    "roda": "roda",
    "padrino": "padrino",
    "rack": "rack",
    "sidekiq": "sidekiq",
    "good_job": "good_job",
    "solid_queue": "solid_queue",
    "resque": "resque",
}

_GEMFILE_GEM_RE = re.compile(
    r"""^\s*gem\s+['"]([A-Za-z0-9_\-]+)['"]""",
    re.MULTILINE,
)


def _ruby_manifest(pkg_dir: Path) -> Path | None:
    """Return the most authoritative Ruby manifest in ``pkg_dir``.

    Preference order: ``Gemfile`` (Bundler — most common) > ``*.gemspec`` (gem
    library) > ``config/application.rb`` (Rails project without Gemfile, rare).
    """
    if (pkg_dir / "Gemfile").is_file():
        return pkg_dir / "Gemfile"
    for gemspec in pkg_dir.glob("*.gemspec"):
        if gemspec.is_file():
            return gemspec
    if (pkg_dir / "config" / "application.rb").is_file():
        return pkg_dir / "config" / "application.rb"
    return None


def _project_name_ruby(manifest: Path) -> str:
    """Best-effort Ruby project name from .gemspec or directory."""
    parent_name = manifest.parent.name or "ruby"
    if manifest.suffix == ".gemspec":
        # ``.gemspec`` files are Ruby — the canonical pattern is
        # ``s.name = 'name'`` or ``spec.name = "name"``.
        match = re.search(
            r"""\.name\s*=\s*['"]([A-Za-z0-9_.\-]+)['"]""",
            manifest.read_text(encoding="utf-8", errors="replace"),
        )
        if match:
            return match.group(1)
    return parent_name


def _detect_ruby_frameworks(pkg_dir: Path) -> set[str]:
    gemfile = pkg_dir / "Gemfile"
    if not gemfile.is_file():
        return set()
    text = gemfile.read_text(encoding="utf-8", errors="replace")
    declared = {m.lower() for m in _GEMFILE_GEM_RE.findall(text)}
    frameworks = {label for gem, label in _RUBY_FRAMEWORK_GEMS.items() if gem in declared}
    if (pkg_dir / "config" / "application.rb").is_file() and "rails" not in frameworks:
        # An ``application.rb`` under config/ implies a Rails app even when
        # the Gemfile doesn't pin rails directly (e.g. via a meta-gem).
        frameworks.add("rails")
    return frameworks


def _detect_ruby_package_manager(pkg_dir: Path) -> str:
    if (pkg_dir / "Gemfile.lock").is_file():
        return "bundler"
    if (pkg_dir / "Gemfile").is_file():
        return "bundler"
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


def _detect_ruby_projects(root: Path, claimed_dirs: set[Path]) -> list[Project]:
    """Find Ruby projects: one per Gemfile / ``*.gemspec`` / ``config/application.rb``."""
    candidates: list[Path] = []
    for needle in ("Gemfile", "*.gemspec"):
        for path in root.rglob(needle):
            rel = path.relative_to(root)
            if any(part in _SKIP_DIRS for part in rel.parts):
                continue
            candidates.append(path.parent)
    # Rails apps without a Gemfile in the repo root (rare but possible).
    for path in root.rglob("config/application.rb"):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        candidates.append(path.parent.parent)
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
        manifest = _ruby_manifest(pkg_dir)
        if manifest is None:
            continue
        projects.append(
            Project(
                name=_project_name_ruby(manifest),
                kind=ProjectKind.RUBY,
                base_path=rel,
                languages=_detect_languages(pkg_dir),
                has_tsconfig=False,
                is_workspace_member=False,
                workspace_root=None,
                frameworks=_detect_ruby_frameworks(pkg_dir),
                package_manager=_detect_ruby_package_manager(pkg_dir),
            )
        )
    return projects


def _detect_csharp_projects(root: Path, claimed_dirs: set[Path]) -> list[Project]:  # noqa: PLR0912 - branches mirror the candidate / claimed / descendant rules
    """Find C#/.NET projects: one per ``*.csproj`` (or ``*.sln`` at root).

    A solution-only repo (``*.sln`` plus per-project ``*.csproj`` under
    subdirectories) emits one project per ``*.csproj`` so each module's
    framework + dependency footprint is visible. The outermost ``*.sln``
    by itself counts when no ``.csproj`` siblings exist (rare but possible
    for sln-only metadata).
    """
    csproj_dirs: set[Path] = set()
    sln_dirs: set[Path] = set()
    for path in root.rglob("*.csproj"):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        csproj_dirs.add(path.parent)
    for path in root.rglob("*.sln"):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        sln_dirs.add(path.parent)
    # When ``*.sln`` lives at a directory that is an ancestor of any
    # ``*.csproj``, treat the sln as a workspace-style wrapper and emit the
    # csproj children only. A standalone sln (no descendant csproj) is
    # rare but still emits one project for completeness.
    candidate_set: set[Path] = set(csproj_dirs)
    for sln_dir in sln_dirs:
        sln_rel = sln_dir.relative_to(root)
        has_descendant_csproj = any(
            _is_descendant(d.relative_to(root), sln_rel) or d == sln_dir for d in csproj_dirs
        )
        if not has_descendant_csproj:
            candidate_set.add(sln_dir)
    candidates: list[Path] = sorted(candidate_set, key=lambda p: len(p.parts))

    selected: list[Path] = []
    for cand in candidates:
        rel = cand.relative_to(root)
        if rel in claimed_dirs:
            continue
        # C# multi-module solutions ship multiple *.csproj — emit one project
        # per csproj rather than collapsing under the outer .sln, since each
        # csproj has its own framework/dependency footprint. Only skip
        # candidates that have an ancestor with a *.csproj already selected.
        ancestor_with_csproj = False
        for sel in selected:
            if _is_descendant(rel, sel) and any((root / sel).glob("*.csproj")):
                ancestor_with_csproj = True
                break
        if ancestor_with_csproj:
            continue
        selected.append(rel)

    projects: list[Project] = []
    for rel in selected:
        pkg_dir = root / rel
        manifest = _csharp_manifest(pkg_dir)
        if manifest is None:
            continue
        projects.append(
            Project(
                name=_project_name_csharp(manifest),
                kind=ProjectKind.CSHARP,
                base_path=rel,
                languages=_detect_languages(pkg_dir),
                has_tsconfig=False,
                is_workspace_member=False,
                workspace_root=None,
                frameworks=_detect_csharp_frameworks(pkg_dir),
                package_manager=_detect_csharp_package_manager(pkg_dir),
            )
        )
    return projects


def _detect_php_projects(root: Path, claimed_dirs: set[Path]) -> list[Project]:
    """Find PHP projects: one per composer.json / wp-config.php / Drupal core marker."""
    candidates: list[Path] = []
    for needle in ("composer.json", "wp-config.php"):
        for path in root.rglob(needle):
            rel = path.relative_to(root)
            if any(part in _SKIP_DIRS for part in rel.parts):
                continue
            candidates.append(path.parent)
    for path in root.rglob("core/lib/Drupal.php"):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        # Drupal marker is at <root>/core/lib/Drupal.php — point at the parent
        # of ``core/`` so the project's base_path lands at the actual project root.
        candidates.append(path.parent.parent.parent)
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
        manifest = _php_manifest(pkg_dir)
        if manifest is None:
            continue
        projects.append(
            Project(
                name=_project_name_php(manifest),
                kind=ProjectKind.PHP,
                base_path=rel,
                languages=_detect_languages(pkg_dir),
                has_tsconfig=False,
                is_workspace_member=False,
                workspace_root=None,
                frameworks=_detect_php_frameworks(pkg_dir),
                package_manager=_detect_php_package_manager(pkg_dir),
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
    projects.extend(_detect_ruby_projects(root, claimed_dirs))
    projects.extend(_detect_php_projects(root, claimed_dirs))
    projects.extend(_detect_csharp_projects(root, claimed_dirs))

    if not projects:
        projects.extend(_detect_bare_source_projects(root))

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


# Mapping from a single source-file extension to the project kind we'd emit
# in bare-source mode. Order doesn't matter — a directory with a mix of
# languages produces one project per kind.
_BARE_SOURCE_KIND_BY_EXT: tuple[tuple[str, ProjectKind, str], ...] = (
    (".py", ProjectKind.PYTHON, "python"),
    (".java", ProjectKind.JAVA, "java"),
    (".go", ProjectKind.GO, "go"),
    (".rb", ProjectKind.RUBY, "ruby"),
    (".php", ProjectKind.PHP, "php"),
    (".cs", ProjectKind.CSHARP, "csharp"),
)


def _detect_bare_source_projects(root: Path) -> list[Project]:
    """Fall back to source-extension detection when no manifest was found.

    Triggers only when no manifest-based project was detected (the caller
    guards with ``if not projects:``). Emits one Project per supported
    language whose source extension appears at least once under ``root``.
    Useful for snippet repos, one-off scripts, and CTF challenges that
    ship without packaging metadata.

    The emitted Project carries:
      * ``name`` = ``root.name`` (the snapshot directory's name)
      * ``base_path`` = ``Path(".")``
      * ``frameworks`` = empty (no manifest to draw deps from)
      * ``package_manager`` = ``"unknown"``
    """
    projects: list[Project] = []
    for ext, kind, lang in _BARE_SOURCE_KIND_BY_EXT:
        if any(_iter_files(root, ext)):
            projects.append(
                Project(
                    name=root.name,
                    kind=kind,
                    base_path=Path("."),
                    languages={lang},
                    has_tsconfig=False,
                    is_workspace_member=False,
                    workspace_root=None,
                    frameworks=set(),
                    package_manager="unknown",
                )
            )
    return projects
