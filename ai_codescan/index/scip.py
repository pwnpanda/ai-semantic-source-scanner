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


def _build_scip_typescript(project_root: Path, *, scip_path: Path) -> None:
    if shutil.which("scip-typescript") is None:
        raise RuntimeError(
            "scip-typescript is not on PATH; install via npm i -g @sourcegraph/scip-typescript"
        )
    # S603/S607: literal argv with "scip-typescript" resolved on PATH; no shell.
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "scip-typescript",
            "index",
            "--infer-tsconfig",
            "--output",
            str(scip_path),
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
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
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "scip-python",
            "index",
            "--project-name",
            project_id,
            "--project-version",
            "0.0.0",
            ".",
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
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


def _ignore_scip_java_workspace_entries(directory: str, entries: list[str]) -> set[str]:
    """Omit dependency trees, generated output, and links from a build workspace."""
    parent = Path(directory)
    return {
        entry for entry in entries if entry in IGNORED_SOURCE_DIRS or (parent / entry).is_symlink()
    }


def _copy_scip_java_workspace(project_root: Path, *, destination: Path) -> Path:
    workspace = destination / "project"
    shutil.copytree(
        project_root,
        workspace,
        ignore=_ignore_scip_java_workspace_entries,
    )
    _make_owner_writable(workspace)
    return workspace


def _run_scip_java(workspace: Path, *, scip_path: Path) -> None:
    subprocess.run(  # noqa: S603 - literal argv, no shell
        ["scip-java", "index", "--output", str(scip_path)],  # noqa: S607
        cwd=workspace,
        check=True,
        capture_output=True,
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


def _build_scip_java(project_root: Path, *, scip_path: Path) -> None:
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
    scip_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="scip-java-",
        dir=scip_path.parent,
        ignore_cleanup_errors=True,
    ) as temp_dir:
        workspace = _copy_scip_java_workspace(project_root, destination=Path(temp_dir))
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
    subprocess.run(  # noqa: S603
        ["scip-go", "--output", str(scip_path)],  # noqa: S607
        cwd=project_root,
        check=True,
        capture_output=True,
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
) -> IndexResult:
    """Run the appropriate SCIP indexer for ``language`` and return the .scip path."""
    project_id = normalize_artifact_id(project_id)
    out_dir = cache_dir / "scip"
    out_dir.mkdir(parents=True, exist_ok=True)
    scip_path = out_dir / f"{project_id}.scip"

    if language == "javascript":
        _build_scip_typescript(project_root, scip_path=scip_path)
    elif language == "python":
        _build_scip_python(project_root, scip_path=scip_path, project_id=project_id)
    elif language == "java":
        _build_scip_java(project_root, scip_path=scip_path)
    elif language == "go":
        _build_scip_go(project_root, scip_path=scip_path)
    else:
        raise ValueError(f"unsupported scip language: {language!r}")
    return IndexResult(scip_path=scip_path, project_id=project_id)
