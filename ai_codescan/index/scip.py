"""Run language-appropriate SCIP indexers and stream the resulting Index protobuf.

Currently dispatches to:
  - ``scip-typescript`` for JavaScript / TypeScript projects.
  - ``scip-python`` (Sourcegraph, Pyright-based) for Python projects.

Each indexer is opt-in: if its CLI isn't on PATH, ``build_scip_index``
raises ``RuntimeError`` and the caller treats SCIP as unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from ai_codescan.third_party import scip_pb2


@dataclass(frozen=True, slots=True)
class IndexResult:
    """Outcome of a successful SCIP index build."""

    scip_path: Path
    project_id: str

    def iter_documents(self) -> Iterator[scip_pb2.Document]:  # ty: ignore[unresolved-attribute]
        """Yield each ``scip_pb2.Document`` from the index."""
        index = scip_pb2.Index()  # ty: ignore[unresolved-attribute]
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
    # S603/S607: literal argv with "scip-python" resolved on PATH; no shell.
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "scip-python",
            "index",
            "--project-name",
            project_id,
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


def build_scip_index(
    project_root: Path,
    *,
    cache_dir: Path,
    project_id: str,
    language: str = "javascript",
) -> IndexResult:
    """Run the appropriate SCIP indexer for ``language`` and return the .scip path."""
    out_dir = cache_dir / "scip"
    out_dir.mkdir(parents=True, exist_ok=True)
    scip_path = out_dir / f"{project_id}.scip"

    if language == "javascript":
        _build_scip_typescript(project_root, scip_path=scip_path)
    elif language == "python":
        _build_scip_python(project_root, scip_path=scip_path, project_id=project_id)
    else:
        raise ValueError(f"unsupported scip language: {language!r}")
    return IndexResult(scip_path=scip_path, project_id=project_id)
