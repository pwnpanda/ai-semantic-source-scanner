"""Run scip-typescript and stream the resulting Index protobuf."""

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


def build_scip_index(project_root: Path, *, cache_dir: Path, project_id: str) -> IndexResult:
    """Run ``scip-typescript`` against ``project_root`` and persist the .scip blob."""
    if shutil.which("scip-typescript") is None:
        raise RuntimeError(
            "scip-typescript is not on PATH; install via npm i -g @sourcegraph/scip-typescript"
        )

    out_dir = cache_dir / "scip"
    out_dir.mkdir(parents=True, exist_ok=True)
    scip_path = out_dir / f"{project_id}.scip"

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
    return IndexResult(scip_path=scip_path, project_id=project_id)
