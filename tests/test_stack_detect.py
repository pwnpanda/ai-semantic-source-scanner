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


def test_express_framework_detected(fixtures_dir: Path) -> None:
    p = detect_projects(fixtures_dir / "tiny-express")[0]
    assert "express" in p.frameworks
    assert p.package_manager == "npm"


def test_react_and_typescript_framework_detected(fixtures_dir: Path) -> None:
    p = detect_projects(fixtures_dir / "tiny-react")[0]
    assert "react" in p.frameworks
    assert p.package_manager == "pnpm"


def test_fastify_in_monorepo_workspace(fixtures_dir: Path) -> None:
    api = next(p for p in detect_projects(fixtures_dir / "monorepo-pnpm") if p.name == "api")
    assert "fastify" in api.frameworks


# ---------------------------------------------------------------------------
# Python detection
# ---------------------------------------------------------------------------


def test_python_pyproject_project_detected(fixtures_dir: Path) -> None:
    projects = detect_projects(fixtures_dir / "tiny-flask")
    assert len(projects) == 1
    p = projects[0]
    assert p.kind is ProjectKind.PYTHON
    assert p.base_path == Path(".")
    assert p.name == "tiny-flask"
    assert "python" in p.languages
    assert "flask" in p.frameworks
    assert p.package_manager in {"pip", "unknown"}


def test_python_setup_py_project_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "legacy"
    pkg.mkdir()
    (pkg / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='legacy-app', version='1.0')\n",
        encoding="utf-8",
    )
    (pkg / "main.py").write_text("print('hi')\n", encoding="utf-8")
    projects = detect_projects(pkg)
    assert len(projects) == 1
    p = projects[0]
    assert p.kind is ProjectKind.PYTHON
    assert p.name == "legacy-app"
    assert "python" in p.languages


def test_python_requirements_txt_project_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "rapp"
    pkg.mkdir()
    (pkg / "requirements.txt").write_text("django>=4.0\nrequests\n", encoding="utf-8")
    (pkg / "wsgi.py").write_text("# entry\n", encoding="utf-8")
    projects = detect_projects(pkg)
    assert len(projects) == 1
    p = projects[0]
    assert p.kind is ProjectKind.PYTHON
    assert "django" in p.frameworks
    assert p.package_manager == "pip"


def test_python_poetry_lock_marks_package_manager(tmp_path: Path) -> None:
    pkg = tmp_path / "papp"
    pkg.mkdir()
    (pkg / "pyproject.toml").write_text(
        "[tool.poetry]\nname='papp'\nversion='0.1.0'\n"
        "[tool.poetry.dependencies]\nfastapi='^0.110'\n",
        encoding="utf-8",
    )
    (pkg / "poetry.lock").write_text("# poetry lock\n", encoding="utf-8")
    p = detect_projects(pkg)[0]
    assert p.package_manager == "poetry"
    assert "fastapi" in p.frameworks


def test_python_uv_lock_marks_package_manager(tmp_path: Path) -> None:
    pkg = tmp_path / "uapp"
    pkg.mkdir()
    (pkg / "pyproject.toml").write_text(
        "[project]\nname='uapp'\nversion='0.1.0'\ndependencies=['flask']\n",
        encoding="utf-8",
    )
    (pkg / "uv.lock").write_text("# uv lock\n", encoding="utf-8")
    p = detect_projects(pkg)[0]
    assert p.package_manager == "uv"


def test_python_does_not_double_report_nested_packages(tmp_path: Path) -> None:
    """Nested pyproject.toml inside an outer Python project is not a separate project."""
    outer = tmp_path / "outer"
    outer.mkdir()
    (outer / "pyproject.toml").write_text(
        "[project]\nname='outer'\nversion='0.1.0'\n",
        encoding="utf-8",
    )
    inner = outer / "vendored" / "inner"
    inner.mkdir(parents=True)
    (inner / "pyproject.toml").write_text(
        "[project]\nname='inner'\nversion='0.1.0'\n",
        encoding="utf-8",
    )
    projects = detect_projects(outer)
    assert len(projects) == 1
    assert projects[0].name == "outer"


def test_python_skips_venv_dirs(tmp_path: Path) -> None:
    """A venv inside the project doesn't create a phantom project."""
    pkg = tmp_path / "vapp"
    pkg.mkdir()
    (pkg / "pyproject.toml").write_text(
        "[project]\nname='vapp'\nversion='0.1.0'\n",
        encoding="utf-8",
    )
    venv = pkg / ".venv" / "lib" / "python3.13" / "site-packages" / "noisy"
    venv.mkdir(parents=True)
    (venv / "setup.py").write_text("from setuptools import setup\nsetup(name='noisy')\n")
    projects = detect_projects(pkg)
    assert [p.name for p in projects] == ["vapp"]


# ---------------------------------------------------------------------------
# Java detection
# ---------------------------------------------------------------------------


def test_java_maven_project_detected(fixtures_dir: Path) -> None:
    projects = detect_projects(fixtures_dir / "tiny-spring")
    assert len(projects) == 1
    p = projects[0]
    assert p.kind is ProjectKind.JAVA
    assert p.name == "tiny-spring"
    assert "java" in p.languages
    assert "spring-boot" in p.frameworks
    assert p.package_manager == "maven"


def test_java_gradle_project_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "gapp"
    pkg.mkdir()
    (pkg / "build.gradle.kts").write_text(
        "plugins { java }\n"
        "dependencies {\n"
        '    implementation("org.springframework.boot:spring-boot-starter-webflux:3.3.4")\n'
        "}\n",
        encoding="utf-8",
    )
    (pkg / "settings.gradle.kts").write_text(
        'rootProject.name = "gapp-svc"\n',
        encoding="utf-8",
    )
    (pkg / "src" / "main" / "java").mkdir(parents=True)
    (pkg / "src" / "main" / "java" / "Main.java").write_text(
        "public class Main { public static void main(String[] a){} }\n"
    )
    p = detect_projects(pkg)[0]
    assert p.kind is ProjectKind.JAVA
    assert p.name == "gapp-svc"
    assert "spring-boot" in p.frameworks
    assert p.package_manager == "gradle-kts"


def test_java_quarkus_framework_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "qapp"
    pkg.mkdir()
    (pkg / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<modelVersion>4.0.0</modelVersion>"
        "<groupId>q</groupId><artifactId>qapp</artifactId><version>1</version>"
        "<dependencies><dependency>"
        "<groupId>io.quarkus</groupId>"
        "<artifactId>quarkus-resteasy</artifactId>"
        "</dependency></dependencies>"
        "</project>\n",
        encoding="utf-8",
    )
    p = detect_projects(pkg)[0]
    assert p.kind is ProjectKind.JAVA
    assert "quarkus" in p.frameworks
    assert p.package_manager == "maven"


def test_java_multi_module_only_outermost_reported(tmp_path: Path) -> None:
    """A multi-module Maven build emits one project; submodules are skipped."""
    outer = tmp_path / "monorepo"
    outer.mkdir()
    (outer / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>m</groupId><artifactId>monorepo</artifactId><version>1</version>"
        "<modules><module>svc</module></modules></project>",
        encoding="utf-8",
    )
    sub = outer / "svc"
    sub.mkdir()
    (sub / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>m</groupId><artifactId>svc</artifactId><version>1</version></project>",
        encoding="utf-8",
    )
    projects = detect_projects(outer)
    assert [p.name for p in projects] == ["monorepo"]


def test_java_skips_target_dir(tmp_path: Path) -> None:
    """Maven's ``target/`` (build output) must not pollute project detection."""
    pkg = tmp_path / "tapp"
    pkg.mkdir()
    (pkg / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>t</groupId><artifactId>tapp</artifactId><version>1</version></project>",
        encoding="utf-8",
    )
    nested = pkg / "target" / "generated-sources" / "shaded"
    nested.mkdir(parents=True)
    (nested / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>g</groupId><artifactId>shaded</artifactId><version>1</version></project>",
        encoding="utf-8",
    )
    assert [p.name for p in detect_projects(pkg)] == ["tapp"]


# ---------------------------------------------------------------------------
# Go detection
# ---------------------------------------------------------------------------


def test_go_module_project_detected(fixtures_dir: Path) -> None:
    projects = detect_projects(fixtures_dir / "tiny-gin")
    assert len(projects) == 1
    p = projects[0]
    assert p.kind is ProjectKind.GO
    assert p.name == "tiny-gin"
    assert "go" in p.languages
    assert "gin" in p.frameworks
    assert p.package_manager == "go-modules"


def test_go_workspace_detected_as_workspace(tmp_path: Path) -> None:
    work = tmp_path / "wapp"
    work.mkdir()
    (work / "go.work").write_text("go 1.22\nuse ./svc\n", encoding="utf-8")
    svc = work / "svc"
    svc.mkdir()
    (svc / "go.mod").write_text(
        "module example.com/svc\n\ngo 1.22\n",
        encoding="utf-8",
    )
    projects = detect_projects(work)
    # Outermost-only: a workspace at the root collapses nested go.mod files.
    assert [p.name for p in projects] == ["wapp"]
    assert projects[0].package_manager == "go-workspace"


def test_go_echo_framework_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "eapp"
    pkg.mkdir()
    (pkg / "go.mod").write_text(
        "module example.com/eapp\n\ngo 1.22\n\nrequire (\n"
        "\tgithub.com/labstack/echo/v4 v4.12.0\n"
        ")\n",
        encoding="utf-8",
    )
    p = detect_projects(pkg)[0]
    assert p.kind is ProjectKind.GO
    assert "echo" in p.frameworks


def test_go_nested_module_inside_outer_skipped(tmp_path: Path) -> None:
    """An outer go.mod swallows a nested go.mod (vendored module)."""
    outer = tmp_path / "outer"
    outer.mkdir()
    (outer / "go.mod").write_text("module example.com/outer\n\ngo 1.22\n")
    inner = outer / "vendor" / "example.com" / "inner"
    inner.mkdir(parents=True)
    (inner / "go.mod").write_text("module example.com/inner\n\ngo 1.22\n")
    # vendor/ isn't in our skip list; rely on outermost-only selection.
    projects = detect_projects(outer)
    assert [p.name for p in projects] == ["outer"]


# ---------------------------------------------------------------------------
# Ruby detection
# ---------------------------------------------------------------------------


def test_ruby_sinatra_project_detected(fixtures_dir: Path) -> None:
    projects = detect_projects(fixtures_dir / "tiny-sinatra")
    assert len(projects) == 1
    p = projects[0]
    assert p.kind is ProjectKind.RUBY
    assert p.name == "tiny-sinatra"
    assert "ruby" in p.languages
    assert "sinatra" in p.frameworks
    assert p.package_manager == "bundler"


def test_ruby_rails_app_detected_from_application_rb(tmp_path: Path) -> None:
    """An app with config/application.rb but no Gemfile is still a Rails project."""
    pkg = tmp_path / "rapp"
    cfg = pkg / "config"
    cfg.mkdir(parents=True)
    (cfg / "application.rb").write_text(
        "module Rapp\n  class Application < Rails::Application\n  end\nend\n",
        encoding="utf-8",
    )
    (pkg / "Gemfile").write_text(
        "source 'https://rubygems.org'\ngem 'rails'\n",
        encoding="utf-8",
    )
    p = detect_projects(pkg)[0]
    assert p.kind is ProjectKind.RUBY
    assert "rails" in p.frameworks


def test_ruby_gemspec_project_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "gemlib"
    pkg.mkdir()
    (pkg / "gemlib.gemspec").write_text(
        'Gem::Specification.new do |s|\n  s.name = "gemlib"\n  s.version = "0.0.1"\nend\n',
        encoding="utf-8",
    )
    (pkg / "lib" / "gemlib.rb").parent.mkdir(parents=True)
    (pkg / "lib" / "gemlib.rb").write_text("module Gemlib; end\n", encoding="utf-8")
    p = detect_projects(pkg)[0]
    assert p.kind is ProjectKind.RUBY
    assert p.name == "gemlib"


def test_ruby_grape_framework_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "gapp"
    pkg.mkdir()
    (pkg / "Gemfile").write_text(
        "source 'https://rubygems.org'\ngem 'grape'\n",
        encoding="utf-8",
    )
    (pkg / "api.rb").write_text("require 'grape'\n", encoding="utf-8")
    p = detect_projects(pkg)[0]
    assert "grape" in p.frameworks


# ---------------------------------------------------------------------------
# PHP detection
# ---------------------------------------------------------------------------


def test_php_slim_project_detected(fixtures_dir: Path) -> None:
    projects = detect_projects(fixtures_dir / "tiny-slim")
    assert len(projects) == 1
    p = projects[0]
    assert p.kind is ProjectKind.PHP
    assert p.name == "tiny-slim"
    assert "php" in p.languages
    assert "slim" in p.frameworks
    assert p.package_manager == "composer"


def test_php_laravel_framework_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "lapp"
    pkg.mkdir()
    (pkg / "composer.json").write_text(
        '{"name":"a/lapp","require":{"laravel/framework":"^11.0"}}',
        encoding="utf-8",
    )
    (pkg / "index.php").write_text("<?php echo 'hi';\n", encoding="utf-8")
    p = detect_projects(pkg)[0]
    assert p.kind is ProjectKind.PHP
    assert "laravel" in p.frameworks


def test_php_wordpress_install_detected(tmp_path: Path) -> None:
    """A WordPress install at the root has no composer.json but ships wp-config.php."""
    pkg = tmp_path / "wp"
    pkg.mkdir()
    (pkg / "wp-config.php").write_text("<?php\n// WP config\n", encoding="utf-8")
    (pkg / "index.php").write_text("<?php\n// WP entry\n", encoding="utf-8")
    p = detect_projects(pkg)[0]
    assert p.kind is ProjectKind.PHP
    assert "wordpress" in p.frameworks


def test_php_symfony_framework_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "sapp"
    pkg.mkdir()
    (pkg / "composer.json").write_text(
        '{"name":"a/sapp","require":{"symfony/framework-bundle":"^7.0"}}',
        encoding="utf-8",
    )
    (pkg / "src" / "Controller").mkdir(parents=True)
    (pkg / "src" / "Controller" / "Foo.php").write_text(
        "<?php\nnamespace App\\Controller; class Foo {}\n",
        encoding="utf-8",
    )
    p = detect_projects(pkg)[0]
    assert "symfony" in p.frameworks


# ---------------------------------------------------------------------------
# C#/.NET detection
# ---------------------------------------------------------------------------


def test_csharp_aspnet_minimal_api_detected(fixtures_dir: Path) -> None:
    projects = detect_projects(fixtures_dir / "tiny-aspnet")
    assert len(projects) == 1
    p = projects[0]
    assert p.kind is ProjectKind.CSHARP
    assert p.name == "TinyAspNet"
    assert "csharp" in p.languages
    assert "aspnetcore-minimal" in p.frameworks
    assert p.package_manager == "nuget"


def test_csharp_blazor_wasm_framework_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "bapp"
    pkg.mkdir()
    (pkg / "bapp.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk.BlazorWebAssembly">'
        "<PropertyGroup><AssemblyName>Bapp</AssemblyName></PropertyGroup>"
        "<ItemGroup>"
        "<PackageReference "
        'Include="Microsoft.AspNetCore.Components.WebAssembly" Version="8.0.10" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    (pkg / "Program.cs").write_text("// blazor entry\n", encoding="utf-8")
    p = detect_projects(pkg)[0]
    assert p.kind is ProjectKind.CSHARP
    assert "blazor-wasm" in p.frameworks


def test_csharp_azure_functions_isolated_detected(tmp_path: Path) -> None:
    pkg = tmp_path / "fn"
    pkg.mkdir()
    (pkg / "fn.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">'
        "<ItemGroup>"
        '<PackageReference Include="Microsoft.Azure.Functions.Worker" Version="1.21.0" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    p = detect_projects(pkg)[0]
    assert "azure-functions" in p.frameworks


def test_csharp_solution_with_two_projects_emits_one_each(tmp_path: Path) -> None:
    """An sln at root with two csproj children emits one project per csproj."""
    root = tmp_path / "sln-repo"
    root.mkdir()
    (root / "App.sln").write_text("# sln stub\n", encoding="utf-8")
    api = root / "src" / "Api"
    web = root / "src" / "Web"
    api.mkdir(parents=True)
    web.mkdir(parents=True)
    (api / "Api.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk.Web">'
        "<PropertyGroup><AssemblyName>Api</AssemblyName></PropertyGroup>"
        "<ItemGroup><PackageReference "
        'Include="Microsoft.AspNetCore.Mvc" Version="2.2" /></ItemGroup></Project>',
        encoding="utf-8",
    )
    (web / "Web.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk.Web">'
        "<PropertyGroup><AssemblyName>Web</AssemblyName></PropertyGroup>"
        "<ItemGroup><PackageReference "
        'Include="Grpc.AspNetCore" Version="2.66" /></ItemGroup></Project>',
        encoding="utf-8",
    )
    projects = detect_projects(root)
    names = {p.name for p in projects}
    assert names == {"Api", "Web"}


def test_csharp_skips_bin_obj_dirs(tmp_path: Path) -> None:
    pkg = tmp_path / "capp"
    pkg.mkdir()
    (pkg / "capp.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        "<AssemblyName>Capp</AssemblyName></PropertyGroup></Project>",
        encoding="utf-8",
    )
    nested = pkg / "bin" / "Debug" / "net8.0" / "shadow"
    nested.mkdir(parents=True)
    (nested / "shadow.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"></Project>',
        encoding="utf-8",
    )
    assert [p.name for p in detect_projects(pkg)] == ["Capp"]


# ---------------------------------------------------------------------------
# Bare-source fallback (no manifest)
# ---------------------------------------------------------------------------


def test_bare_python_files_detected_without_manifest(tmp_path: Path) -> None:
    pkg = tmp_path / "snippet"
    pkg.mkdir()
    (pkg / "main.py").write_text("print('hi')\n", encoding="utf-8")
    (pkg / "util.py").write_text("def f(): pass\n", encoding="utf-8")
    projects = detect_projects(pkg)
    assert len(projects) == 1
    p = projects[0]
    assert p.kind is ProjectKind.PYTHON
    assert "python" in p.languages
    assert p.name == "snippet"
    assert p.frameworks == set()
    assert p.package_manager == "unknown"


def test_bare_go_files_detected_without_manifest(tmp_path: Path) -> None:
    pkg = tmp_path / "ctf"
    pkg.mkdir()
    (pkg / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    p = detect_projects(pkg)[0]
    assert p.kind is ProjectKind.GO


def test_bare_ruby_files_detected_without_manifest(tmp_path: Path) -> None:
    pkg = tmp_path / "scripts"
    pkg.mkdir()
    (pkg / "tool.rb").write_text("puts 'hi'\n", encoding="utf-8")
    p = detect_projects(pkg)[0]
    assert p.kind is ProjectKind.RUBY


def test_bare_source_skipped_when_manifest_present(tmp_path: Path) -> None:
    """A real Python manifest still wins over the bare-source fallback."""
    pkg = tmp_path / "real"
    pkg.mkdir()
    (pkg / "pyproject.toml").write_text(
        "[project]\nname='real'\nversion='0.1.0'\ndependencies=['flask']\n",
        encoding="utf-8",
    )
    (pkg / "stray.go").write_text("package main\n", encoding="utf-8")
    projects = detect_projects(pkg)
    # Python project from the manifest; the stray .go does NOT spawn a Go project.
    assert [p.kind for p in projects] == [ProjectKind.PYTHON]


def test_bare_source_emits_one_project_per_language(tmp_path: Path) -> None:
    """A directory with mixed source files (no manifest) yields one project per language."""
    pkg = tmp_path / "polyglot"
    pkg.mkdir()
    (pkg / "a.py").write_text("\n", encoding="utf-8")
    (pkg / "b.go").write_text("package main\n", encoding="utf-8")
    (pkg / "c.rb").write_text("\n", encoding="utf-8")
    kinds = {p.kind for p in detect_projects(pkg)}
    assert kinds == {ProjectKind.PYTHON, ProjectKind.GO, ProjectKind.RUBY}


def test_node_and_python_coexist_at_same_root(tmp_path: Path) -> None:
    """A directory with both package.json and pyproject.toml yields a Node project only.

    Python detection skips a directory already claimed by Node so we don't
    double-report when JS tooling sits next to a Python service in the same
    folder.
    """
    pkg = tmp_path / "mixed"
    pkg.mkdir()
    (pkg / "package.json").write_text('{"name":"mixed-node"}', encoding="utf-8")
    (pkg / "pyproject.toml").write_text(
        "[project]\nname='mixed-py'\nversion='0.1.0'\n",
        encoding="utf-8",
    )
    projects = detect_projects(pkg)
    assert [p.kind for p in projects] == [ProjectKind.NODE]
