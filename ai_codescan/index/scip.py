"""Run language-appropriate SCIP indexers and stream the resulting Index protobuf.

Currently dispatches to:
  - ``scip-typescript`` for JavaScript / TypeScript projects.
  - ``scip-python`` (Sourcegraph, Pyright-based) for Python projects.
  - ``scip-java`` (Sourcegraph, semanticdb / kotlinc-based) for Java + Kotlin.
  - ``scip-go`` (Sourcegraph, gopls-based) for Go modules.

Each indexer is opt-in: if its CLI isn't on PATH, ``build_scip_index``
raises ``RuntimeError`` and the caller treats SCIP as unavailable.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from google.protobuf.message import DecodeError

from ai_codescan.artifact_id import normalize_artifact_id
from ai_codescan.manifest import IGNORED_SOURCE_DIRS
from ai_codescan.third_party import scip_pb2


@dataclass(frozen=True, slots=True)
class IndexResult:
    """Outcome of a successful SCIP index build."""

    scip_path: Path
    project_id: str

    def iter_documents(self) -> Iterator[scip_pb2.Document]:
        """Yield each ``scip_pb2.Document`` from the index."""
        index = scip_pb2.Index()
        index.ParseFromString(self.scip_path.read_bytes())
        yield from index.documents


class ScipDependenciesUnavailableError(RuntimeError):
    """Raised when a project build needs dependencies that are not installed."""


@dataclass(frozen=True, slots=True)
class ScipWorkspace:
    """Map a snapshot project to dependencies in the original workspace."""

    snapshot_root: Path
    project_base_path: Path
    dependency_root: Path | None


def _process_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace").strip()
    return value.strip()


def _run_indexer(argv: list[str], *, cwd: Path, indexer: str) -> None:
    try:
        subprocess.run(argv, cwd=cwd, check=True, capture_output=True)  # noqa: S603
    except subprocess.CalledProcessError as exc:
        detail = _process_output(exc.stderr) or _process_output(exc.stdout) or "no output"
        raise RuntimeError(f"{indexer} failed in {cwd}: {detail[-4000:]}") from exc


def _project_ancestors(base_path: Path) -> tuple[Path, ...]:
    if base_path.is_absolute() or ".." in base_path.parts:
        raise ValueError(f"project base path must stay relative: {base_path}")
    paths = (base_path, *base_path.parents)
    return tuple(dict.fromkeys(paths))


def _node_modules_paths(dependency_root: Path | None, base_path: Path) -> tuple[Path, ...]:
    if dependency_root is None:
        return ()
    return tuple(
        modules
        for relative in _project_ancestors(base_path)
        if (modules := dependency_root / relative / "node_modules").is_dir()
    )


def _copy_scip_workspace(
    project_root: Path,
    *,
    destination: Path,
    config: ScipWorkspace,
) -> Path:
    source_root = destination / "source"
    workspace = source_root / config.project_base_path
    workspace.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        project_root,
        workspace,
        ignore=_ignore_scip_workspace_entries,
    )
    for relative in config.project_base_path.parents:
        source_parent = config.snapshot_root / relative
        destination_parent = source_root / relative
        destination_parent.mkdir(parents=True, exist_ok=True)
        for path in source_parent.iterdir():
            if path.is_file() and not path.is_symlink():
                shutil.copy2(path, destination_parent / path.name)
    _make_owner_writable(source_root)
    if config.dependency_root is None:
        return workspace
    for relative in _project_ancestors(config.project_base_path):
        modules = config.dependency_root / relative / "node_modules"
        if not modules.is_dir():
            continue
        link = source_root / relative / "node_modules"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(modules.resolve(), target_is_directory=True)
    return workspace


@contextmanager
def isolated_node_dependency_workspace(
    source_root: Path,
    *,
    cache_dir: Path,
) -> Iterator[Path]:
    """Provide installed Node dependencies without modifying the source tree."""
    if (source_root / "node_modules").is_dir() or not (source_root / "package-lock.json").is_file():
        yield source_root
        return
    if shutil.which("npm") is None:
        raise ScipDependenciesUnavailableError(
            "npm is not on PATH, so SCIP cannot install locked Node dependencies"
        )
    workspace_parent = cache_dir / "scip"
    workspace_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="scip-node-dependencies-",
        dir=workspace_parent,
        ignore_cleanup_errors=True,
    ) as temp_dir:
        workspace = Path(temp_dir) / "source"
        shutil.copytree(
            source_root,
            workspace,
            ignore=_ignore_scip_workspace_entries,
        )
        _make_owner_writable(workspace)
        _run_indexer(
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=workspace,
            indexer="npm ci",
        )
        yield workspace


def _build_scip_typescript(
    project_root: Path,
    *,
    scip_path: Path,
    workspace_config: ScipWorkspace,
) -> None:
    if shutil.which("scip-typescript") is None:
        raise RuntimeError(
            "scip-typescript is not on PATH; install via npm i -g @sourcegraph/scip-typescript"
        )
    with tempfile.TemporaryDirectory(
        prefix="scip-typescript-",
        dir=scip_path.parent,
        ignore_cleanup_errors=True,
    ) as temp_dir:
        workspace = _copy_scip_workspace(
            project_root,
            destination=Path(temp_dir),
            config=workspace_config,
        )
        _run_indexer(
            [
                "scip-typescript",
                "index",
                "--infer-tsconfig",
                "--output",
                str(scip_path),
            ],
            cwd=workspace,
            indexer="scip-typescript",
        )


def _build_scip_python(project_root: Path, *, scip_path: Path, project_id: str) -> None:
    """Run ``scip-python`` and move the produced ``index.scip`` to ``scip_path``.

    scip-python writes its output as ``index.scip`` in the working directory
    (no ``--output`` flag). We invoke it with cwd=``project_root`` and then
    rename the result so callers see a stable, project-id-keyed path.
    """
    if shutil.which("scip-python") is None:
        raise RuntimeError(
            "scip-python is not on PATH; install via npm i -g @sourcegraph/scip-python"
        )
    # scip-python's ScipSymbol.normalizeNameOrVersion crashes when the
    # project name contains a `.` (it splits on the first dot and tries
    # `.indexOf` on the undefined version half). The public entrypoint has
    # already normalized project_id to a strict slug; an explicit version
    # prevents the same parser bug for every supported scip-python release.
    # scip-python writes index.scip via open(O_WRONLY|O_TRUNC). If a stale
    # read-only index.scip exists from a prior run (snapshot files are
    # often chmod 0444), the open() fails with EACCES. Pre-unlink so the
    # write goes through cleanly.
    stale = project_root / "index.scip"
    if stale.exists():
        stale.chmod(0o644)
        stale.unlink()
    # S603/S607: literal argv with "scip-python" resolved on PATH; no shell.
    _run_indexer(
        [
            "scip-python",
            "index",
            "--project-name",
            project_id,
            "--project-version",
            "0.0.0",
            ".",
        ],
        cwd=project_root,
        indexer="scip-python",
    )
    produced = project_root / "index.scip"
    if not produced.is_file():
        raise RuntimeError(
            f"scip-python did not produce index.scip at {produced} (cwd={project_root})"
        )
    shutil.move(str(produced), str(scip_path))


def _make_owner_writable(root: Path) -> None:
    """Make a copied build workspace writable without following symlinks."""
    root.chmod(root.stat().st_mode | stat.S_IWUSR)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        path.chmod(path.stat().st_mode | stat.S_IWUSR)


def _ignore_scip_workspace_entries(directory: str, entries: list[str]) -> set[str]:
    """Omit dependency trees, generated output, and links from a build workspace."""
    parent = Path(directory)
    return {
        entry for entry in entries if entry in IGNORED_SOURCE_DIRS or (parent / entry).is_symlink()
    }


def _run_scip_java(workspace: Path, *, scip_path: Path) -> None:
    _run_indexer(
        ["scip-java", "index", "--output", str(scip_path)],
        cwd=workspace,
        indexer="scip-java",
    )
    if scip_path.is_file():
        return
    produced = workspace / "index.scip"
    if not produced.is_file():
        raise RuntimeError(
            f"scip-java did not produce a SCIP index at {scip_path} (also checked {produced})"
        )
    shutil.move(str(produced), str(scip_path))


def _validate_prebuilt_scip_java_index(path: Path) -> None:
    index = scip_pb2.Index()
    try:
        index.ParseFromString(path.read_bytes())
    except (DecodeError, OSError) as exc:
        raise RuntimeError(
            f"invalid SCIP-Java prebuilt index at {path}; regenerate it or unset "
            "AI_CODESCAN_SCIP_JAVA_INDEX"
        ) from exc


def _required_gradle_node_packages(project_root: Path) -> tuple[str, ...]:
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for name in ("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts")
        if (path := project_root / name).is_file()
    ).lower()
    required: list[str] = []
    if "@react-native/gradle-plugin" in text or "com.facebook.react" in text:
        required.append("@react-native/gradle-plugin")
    if "expo-modules-autolinking" in text or "expo-autolinking-settings" in text:
        required.append("expo-modules-autolinking")
    return tuple(required)


def _missing_node_packages(
    project_root: Path,
    *,
    workspace_config: ScipWorkspace,
) -> tuple[str, ...]:
    required = _required_gradle_node_packages(project_root)
    module_paths = _node_modules_paths(
        workspace_config.dependency_root,
        workspace_config.project_base_path,
    )
    return tuple(
        package
        for package in required
        if not any((modules / package / "package.json").is_file() for modules in module_paths)
    )


def _build_scip_java(
    project_root: Path,
    *,
    scip_path: Path,
    workspace_config: ScipWorkspace,
) -> None:
    """Run ``scip-java index`` and move the produced index to ``scip_path``.

    scip-java drives the project's existing build (Maven / Gradle) to
    extract semanticdb data, so a working JDK + build tool must be on
    PATH. Output lands at ``index.scip`` inside the project root by
    default; we move it to the cache.
    """
    prebuilt_index = os.environ.get("AI_CODESCAN_SCIP_JAVA_INDEX")
    if prebuilt_index:
        prebuilt_path = Path(prebuilt_index).expanduser().resolve()
        if not prebuilt_path.is_file():
            raise RuntimeError(
                f"AI_CODESCAN_SCIP_JAVA_INDEX does not point to a file: {prebuilt_path}"
            )
        _validate_prebuilt_scip_java_index(prebuilt_path)
        shutil.copy2(prebuilt_path, scip_path)
        return
    if shutil.which("scip-java") is None:
        raise RuntimeError(
            "scip-java is not on PATH; install via "
            "coursier install scip-java (https://sourcegraph.github.io/scip-java/)"
        )
    missing_packages = _missing_node_packages(
        project_root,
        workspace_config=workspace_config,
    )
    if missing_packages:
        missing = ", ".join(missing_packages)
        raise ScipDependenciesUnavailableError(
            f"scip-java requires installed Node packages before indexing this Gradle project: "
            f"{missing}"
        )
    scip_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="scip-java-",
        dir=scip_path.parent,
        ignore_cleanup_errors=True,
    ) as temp_dir:
        workspace = _copy_scip_workspace(
            project_root,
            destination=Path(temp_dir),
            config=workspace_config,
        )
        _run_scip_java(workspace, scip_path=scip_path)


def _build_scip_go(project_root: Path, *, scip_path: Path) -> None:
    """Run ``scip-go`` and move the produced index to ``scip_path``.

    scip-go uses gopls under the hood, which means the host needs the
    ``go`` toolchain on PATH and the module's deps must be resolvable
    via ``go mod download``. Output is ``index.scip`` in cwd.
    """
    if shutil.which("scip-go") is None:
        raise RuntimeError(
            "scip-go is not on PATH; install via "
            "go install github.com/sourcegraph/scip-go/cmd/scip-go@latest"
        )
    # S603/S607: literal argv with "scip-go" resolved on PATH; no shell.
    _run_indexer(
        ["scip-go", "--output", str(scip_path)],
        cwd=project_root,
        indexer="scip-go",
    )
    if not scip_path.is_file():
        produced = project_root / "index.scip"
        if not produced.is_file():
            raise RuntimeError(
                f"scip-go did not produce a SCIP index at {scip_path} (also checked {produced})"
            )
        shutil.move(str(produced), str(scip_path))


def build_scip_index(
    project_root: Path,
    *,
    cache_dir: Path,
    project_id: str,
    language: str = "javascript",
    workspace: ScipWorkspace | None = None,
) -> IndexResult:
    """Run the appropriate SCIP indexer for ``language`` and return the .scip path."""
    project_id = normalize_artifact_id(project_id)
    out_dir = cache_dir / "scip"
    out_dir.mkdir(parents=True, exist_ok=True)
    scip_path = out_dir / f"{project_id}.scip"
    workspace = workspace or ScipWorkspace(
        snapshot_root=project_root,
        project_base_path=Path("."),
        dependency_root=None,
    )

    if language == "javascript":
        _build_scip_typescript(
            project_root,
            scip_path=scip_path,
            workspace_config=workspace,
        )
    elif language == "python":
        _build_scip_python(project_root, scip_path=scip_path, project_id=project_id)
    elif language == "java":
        _build_scip_java(
            project_root,
            scip_path=scip_path,
            workspace_config=workspace,
        )
    elif language == "go":
        _build_scip_go(project_root, scip_path=scip_path)
    else:
        raise ValueError(f"unsupported scip language: {language!r}")
    return IndexResult(scip_path=scip_path, project_id=project_id)
