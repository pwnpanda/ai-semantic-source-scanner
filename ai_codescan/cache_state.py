"""Fingerprint and completion state for reusable scan indexes."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import duckdb

if TYPE_CHECKING:
    from ai_codescan.taxonomy.loader import BugClass

_FINGERPRINT_VERSION = 1
_SCANNER_SUFFIXES = frozenset(
    {".json", ".md", ".mjs", ".py", ".ql", ".qll", ".sc", ".sh", ".yaml", ".yml"}
)
_SCANNER_IGNORED_PARTS = frozenset({"__pycache__", "node_modules"})
_ACTIVE_REPO_CONFIGS = (
    "aics-codeql-extension-packs.json",
    "aics-enabled-packs.json",
    "aics-joern-extension-packs.json",
    "aics-semgrep-rules.json",
)
_TOOLS = (
    "claude",
    "codeql",
    "codex",
    "gemini",
    "joern",
    "joern-parse",
    "node",
    "scip-go",
    "scip-java",
    "scip-python",
    "scip-typescript",
    "semgrep",
)


def _update_file_digest(digest: Any, path: Path, *, label: str) -> None:
    digest.update(label.encode("utf-8"))
    digest.update(b"\0")
    if not path.is_file():
        digest.update(b"missing\0")
        return
    with path.open("rb") as handle:
        while chunk := handle.read(65_536):
            digest.update(chunk)
    digest.update(b"\0")


def _scanner_files(package_root: Path | None = None) -> Iterable[Path]:
    package_root = package_root or Path(__file__).resolve().parent
    for path in sorted(package_root.rglob("*")):
        if not path.is_file() or path.suffix not in _SCANNER_SUFFIXES:
            continue
        if any(part in _SCANNER_IGNORED_PARTS for part in path.relative_to(package_root).parts):
            continue
        yield path


def _tool_identity(tool: str) -> dict[str, object]:
    located = shutil.which(tool)
    if located is None:
        return {"name": tool, "available": False}
    path = Path(located).resolve()
    try:
        stat = path.stat()
    except OSError:
        return {"name": tool, "available": True, "path": str(path)}
    return {
        "name": tool,
        "available": True,
        "path": str(path),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _bug_class_payload(bug_classes: list[BugClass] | None) -> list[dict[str, object]]:
    return [
        {
            "name": item.name,
            "cwes": sorted(item.cwes),
            "codeql_tags": sorted(item.codeql_tags),
            "needs_semantic": item.needs_semantic,
        }
        for item in sorted(bug_classes or [], key=lambda item: item.name)
    ]


def _hash_external_pack_configs(digest: Any, repo_dir: Path) -> None:
    registry = repo_dir / "aics-enabled-packs.json"
    if not registry.is_file():
        return
    try:
        payload = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, list):
        return
    for raw in sorted(str(item) for item in payload):
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = repo_dir / candidate
        if candidate.is_file():
            _update_file_digest(digest, candidate, label=f"enabled-pack:{raw}")


def _hash_source_manifest(digest: Any, manifest_path: Path) -> None:
    """Hash source identity without volatile mtimes from copy/worktree creation."""
    if not manifest_path.is_file():
        digest.update(b"source-manifest\0missing\0")
        return
    entries: list[tuple[str, str, int]] = []
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        entries.append((str(item["path"]), str(item["sha256"]), int(item["size"])))
    digest.update(b"source-manifest\0")
    digest.update(json.dumps(sorted(entries), separators=(",", ":")).encode("utf-8"))
    digest.update(b"\0")


def _active_semgrep_roots(repo_dir: Path) -> list[Path]:
    roots = [repo_dir / ".semgrep"]
    registry = repo_dir / "aics-semgrep-rules.json"
    if not registry.is_file():
        return roots
    try:
        payload = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return roots
    if isinstance(payload, dict) and payload.get("rules_root"):
        roots.append(Path(str(payload["rules_root"])).expanduser())
    return list(dict.fromkeys(root.resolve() for root in roots))


def _hash_active_semgrep_rules(digest: Any, repo_dir: Path) -> None:
    for root in _active_semgrep_roots(repo_dir):
        rules_dir = root.resolve() / "rules"
        if not rules_dir.is_dir():
            digest.update(f"semgrep-rules:{rules_dir}:missing\0".encode())
            continue
        for path in sorted(rules_dir.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.suffix in {".yml", ".yaml"}:
                _update_file_digest(
                    digest,
                    path,
                    label=f"semgrep-rule:{rules_dir}:{path.relative_to(rules_dir)}",
                )


def build_scan_fingerprint(
    repo_dir: Path,
    *,
    engine: str,
    bug_classes: list[BugClass] | None,
    engine_config: dict[str, str] | None = None,
) -> str:
    """Return a digest of every input that can change source-derived scan rows."""
    digest = hashlib.sha256()
    package_root = Path(__file__).resolve().parent
    settings = {
        "version": _FINGERPRINT_VERSION,
        "engine": engine,
        "engine_config": engine_config or {},
        "bug_classes": _bug_class_payload(bug_classes),
        "tools": [_tool_identity(tool) for tool in _TOOLS],
        "scip_java_index": os.environ.get("AI_CODESCAN_SCIP_JAVA_INDEX", ""),
    }
    digest.update(json.dumps(settings, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    for path in _scanner_files():
        _update_file_digest(digest, path, label=path.relative_to(package_root).as_posix())
    _hash_source_manifest(digest, repo_dir / "manifest.jsonl")
    for name in _ACTIVE_REPO_CONFIGS:
        _update_file_digest(digest, repo_dir / name, label=f"repo-config:{name}")
    _hash_external_pack_configs(digest, repo_dir)
    _hash_active_semgrep_rules(digest, repo_dir)
    if prebuilt_index := os.environ.get("AI_CODESCAN_SCIP_JAVA_INDEX"):
        _update_file_digest(
            digest,
            Path(prebuilt_index).expanduser(),
            label="scip-java-prebuilt-index",
        )
    return digest.hexdigest()


def scan_stage_is_current(
    conn: duckdb.DuckDBPyConnection,
    *,
    fingerprint: str,
    engine: str,
    required_stage: str,
) -> bool:
    """Return whether DuckDB records the requested stage for this exact scan input."""
    stage = scan_stage_for_inputs(conn, fingerprint=fingerprint, engine=engine)
    return stage == "complete" or (required_stage == "prep" and stage == "prep")


def scan_stage_for_inputs(
    conn: duckdb.DuckDBPyConnection,
    *,
    fingerprint: str,
    engine: str,
) -> str | None:
    """Return the stored stage when it belongs to the exact requested generation."""
    row = conn.execute(
        "SELECT fingerprint, engine, stage FROM scan_cache_state WHERE singleton = 1"
    ).fetchone()
    if row is None or row[0] != fingerprint or row[1] != engine:
        return None
    return str(row[2])


def scan_db_stage_is_current(
    db_path: Path,
    *,
    fingerprint: str,
    engine: str,
    required_stage: str,
) -> bool:
    """Read :func:`scan_stage_is_current` from a closed, existing database."""
    if not db_path.is_file() or (db_path.parent / ".prep-incomplete").is_file():
        return False
    try:
        conn = duckdb.connect(str(db_path), read_only=True)
    except duckdb.Error:
        return False
    try:
        return scan_stage_is_current(
            conn,
            fingerprint=fingerprint,
            engine=engine,
            required_stage=required_stage,
        )
    except duckdb.Error:
        return False
    finally:
        conn.close()


def scan_db_stage(db_path: Path) -> str | None:
    """Return the published cache stage for orchestration/degraded-run handling."""
    if not db_path.is_file() or (db_path.parent / ".prep-incomplete").is_file():
        return None
    try:
        conn = duckdb.connect(str(db_path), read_only=True)
    except duckdb.Error:
        return None
    try:
        row = conn.execute("SELECT stage FROM scan_cache_state WHERE singleton = 1").fetchone()
        return str(row[0]) if row else None
    except duckdb.Error:
        return None
    finally:
        conn.close()


def set_scan_stage(
    conn: duckdb.DuckDBPyConnection,
    *,
    fingerprint: str,
    engine: str,
    stage: str,
) -> None:
    """Set the authoritative scan stage inside the caller's transaction."""
    if stage not in {
        "prep",
        "prep_with_gaps",
        "complete",
        "complete_unpinned",
        "complete_with_gaps",
    }:
        raise ValueError(f"unsupported scan cache stage: {stage}")
    conn.execute(
        """
        INSERT OR REPLACE INTO scan_cache_state
          (singleton, fingerprint, engine, stage, updated_at)
        VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        [fingerprint, engine, stage],
    )
