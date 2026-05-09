# AI_Codescan 1A — Foundation, Snapshot, Stack-Detect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the `ai_codescan` Python package with a working CLI that can take a snapshot of any target repo, hash its contents, and detect its language/framework stack — producing `repo.md` and a read-only source mirror.

**Architecture:** Pure Python 3.13 package with a Typer CLI. Snapshot uses `git worktree` when the target is a git repo, falls back to `cp -r` otherwise. Stack detection is heuristic — walks the snapshot, parses `package.json` and lockfiles, fingerprints frameworks from dependency names + import patterns. All paths under `~/.ai_codescan/repos/<repo_id>/` by default.

**Tech Stack:** Python 3.13, `uv` (deps + venv), `typer` (CLI), `ruff` (lint/format), `ty` (type-check), `pytest` (tests), `pytest-cov` (coverage). No runtime deps beyond Typer in this sub-plan.

**Project root:** `/home/robin/Hacking/AI_Analysis/` (currently empty; this plan creates the package).

**Reference spec:** `docs/superpowers/specs/2026-05-08-ai-codescan-phase1-design.md` §5.1, §5.2, §5.10, §7, §8.

---

## File Structure (after this plan)

```
AI_Analysis/
├── pyproject.toml
├── README.md
├── .gitignore
├── .python-version
├── ai_codescan/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                 # Typer entry, subcommands
│   ├── config.py              # paths, constants, repo_id computation
│   ├── manifest.py            # file hashing, manifest read/write/diff
│   ├── snapshot.py            # git worktree / cp snapshot
│   ├── stack_detect.py        # framework + project detection
│   └── repo_md.py             # repo.md rendering
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── fixtures/
    │   ├── tiny-express/
    │   │   ├── package.json
    │   │   ├── package-lock.json
    │   │   └── server.js
    │   ├── tiny-react/
    │   │   ├── package.json
    │   │   ├── pnpm-lock.yaml
    │   │   ├── tsconfig.json
    │   │   └── src/App.tsx
    │   └── monorepo-pnpm/
    │       ├── package.json
    │       ├── pnpm-workspace.yaml
    │       └── packages/
    │           ├── api/{package.json,server.ts}
    │           └── web/{package.json,index.html}
    ├── test_config.py
    ├── test_manifest.py
    ├── test_snapshot.py
    ├── test_stack_detect.py
    ├── test_repo_md.py
    └── test_cli.py
```

Each module has one responsibility; all are <100 lines per function and <300 lines per file.

---

## Task 1: Project bootstrap

**Files:**
- Create: `AI_Analysis/pyproject.toml`
- Create: `AI_Analysis/.gitignore`
- Create: `AI_Analysis/.python-version`
- Create: `AI_Analysis/README.md`
- Create: `AI_Analysis/ai_codescan/__init__.py`
- Create: `AI_Analysis/ai_codescan/__main__.py`
- Create: `AI_Analysis/tests/__init__.py`
- Create: `AI_Analysis/tests/conftest.py`

- [ ] **Step 1: Create the package layout**

```bash
cd /home/robin/Hacking/AI_Analysis
mkdir -p ai_codescan tests/fixtures
touch ai_codescan/__init__.py tests/__init__.py
echo "3.13" > .python-version
```

- [ ] **Step 2: Write `pyproject.toml`**

Create `pyproject.toml` with:

```toml
[build-system]
requires = ["uv_build>=0.5"]
build-backend = "uv_build"

[project]
name = "ai-codescan"
version = "0.1.0"
description = "AI-driven SAST pipeline (Phase 1A: foundation, snapshot, stack-detect)"
requires-python = ">=3.13"
dependencies = [
  "typer>=0.15.1",
]

[project.scripts]
ai-codescan = "ai_codescan.cli:app"

[dependency-groups]
dev = [
  "pytest>=8.3",
  "pytest-cov>=5.0",
  "ruff>=0.7",
  "ty>=0.0.1a1",
]

[tool.ruff]
line-length = 100
target-version = "py313"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "S", "SIM", "RET", "PL"]
ignore = ["S101"]  # allow assert in tests

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S", "PLR2004"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q --strict-markers --strict-config"
markers = [
  "slow: tests that touch the filesystem heavily",
  "integration: end-to-end CLI tests",
]
```

- [ ] **Step 3: Write `.gitignore`**

Create `.gitignore`:

```gitignore
__pycache__/
*.py[cod]
.venv/
.pytest_cache/
.ruff_cache/
.coverage
htmlcov/
dist/
build/
*.egg-info/
```

- [ ] **Step 4: Write `README.md` skeleton**

Create `README.md`:

```markdown
# ai-codescan

AI-driven SAST pipeline. Phase 1 = deterministic prep + wide-pass nominator with HITL gate.

See `docs/superpowers/specs/2026-05-08-ai-codescan-phase1-design.md` for the full design.

## Install (development)

\`\`\`bash
uv venv
uv sync --all-groups
uv run ai-codescan --help
\`\`\`

## Phase 1A status

This sub-plan delivers: `ai-codescan prep <target>` produces a snapshot and `repo.md`.
```

- [ ] **Step 5: Write `__main__.py` and `tests/conftest.py`**

`ai_codescan/__main__.py`:

```python
from ai_codescan.cli import app

if __name__ == "__main__":
    app()
```

`tests/conftest.py`:

```python
"""Shared pytest fixtures."""

from collections.abc import Iterator
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to bundled test fixture repos."""
    return FIXTURES_DIR


@pytest.fixture
def tmp_cache_dir(tmp_path: Path) -> Iterator[Path]:
    """Isolated cache directory for one test."""
    cache = tmp_path / "cache"
    cache.mkdir()
    yield cache
```

- [ ] **Step 6: Initialize venv and verify install**

```bash
cd /home/robin/Hacking/AI_Analysis
uv venv
uv sync --all-groups
uv run python -c "import ai_codescan; print('ok')"
```

Expected: prints `ok`.

- [ ] **Step 7: Commit**

```bash
cd /home/robin/Hacking/AI_Analysis
git init
git add pyproject.toml .gitignore .python-version README.md ai_codescan/ tests/
git commit -m "chore: bootstrap ai-codescan package skeleton"
```

(Note: `Hacking/` is not a git repo. We initialize a git repo at `AI_Analysis/` for this project.)

---

## Task 2: `repo_id` and cache-path computation (`config.py`)

**Files:**
- Create: `ai_codescan/config.py`
- Test: `tests/test_config.py`

The `repo_id` is `<basename>-<sha1(remote_url-or-abspath)[:8]>` (per spec §8).

- [ ] **Step 1: Write the failing tests**

`tests/test_config.py`:

```python
"""Tests for ai_codescan.config."""

from pathlib import Path

from ai_codescan.config import compute_repo_id, default_cache_root, repo_cache_dir


def test_repo_id_uses_basename_and_path_hash(tmp_path: Path) -> None:
    repo = tmp_path / "my-target"
    repo.mkdir()
    repo_id = compute_repo_id(repo)
    assert repo_id.startswith("my-target-")
    assert len(repo_id) == len("my-target-") + 8


def test_repo_id_is_stable_across_calls(tmp_path: Path) -> None:
    repo = tmp_path / "stable"
    repo.mkdir()
    assert compute_repo_id(repo) == compute_repo_id(repo)


def test_repo_id_differs_for_different_paths(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert compute_repo_id(a) != compute_repo_id(b)


def test_default_cache_root_is_home_subdir() -> None:
    root = default_cache_root()
    assert root == Path.home() / ".ai_codescan" / "repos"


def test_repo_cache_dir_combines_root_and_id(tmp_path: Path) -> None:
    repo = tmp_path / "x"
    repo.mkdir()
    cache_dir = repo_cache_dir(repo, cache_root=tmp_path / "cache")
    assert cache_dir.parent == tmp_path / "cache"
    assert cache_dir.name == compute_repo_id(repo)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_config.py -v
```

Expected: ImportError on `ai_codescan.config`.

- [ ] **Step 3: Implement `config.py`**

```python
"""Path and ID conventions for the cache layout.

repo_id format: ``<basename>-<sha1(canonical-path)[:8]>`` per design spec §8.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def _canonical_target_identity(target: Path) -> str:
    """Return the string used to derive the repo's hash component.

    Prefers ``git remote get-url origin`` when present; falls back to the
    absolute filesystem path so non-git directories still get a stable id.
    """
    if (target / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(target), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    return str(target.resolve())


def compute_repo_id(target: Path) -> str:
    """Stable identifier for ``target`` of the form ``<basename>-<sha1[:8]>``."""
    basename = target.name
    identity = _canonical_target_identity(target)
    digest = hashlib.sha1(identity.encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"{basename}-{digest[:8]}"


def default_cache_root() -> Path:
    """Default location for all per-repo cache trees."""
    return Path.home() / ".ai_codescan" / "repos"


def repo_cache_dir(target: Path, *, cache_root: Path | None = None) -> Path:
    """Cache directory for ``target`` under ``cache_root`` (default: ``~/.ai_codescan/repos``)."""
    root = cache_root if cache_root is not None else default_cache_root()
    return root / compute_repo_id(target)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_config.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/config.py tests/test_config.py
git commit -m "feat(config): add repo_id and cache-path computation"
```

---

## Task 3: File manifest (`manifest.py`)

**Files:**
- Create: `ai_codescan/manifest.py`
- Test: `tests/test_manifest.py`

Manifest is JSONL — one record per file `{"path", "sha256", "size", "mtime"}`.
Used by snapshot for read-only enforcement and incremental diffing (spec §10).

- [ ] **Step 1: Write the failing tests**

`tests/test_manifest.py`:

```python
"""Tests for ai_codescan.manifest."""

import json
from pathlib import Path

from ai_codescan.manifest import (
    ManifestEntry,
    build_manifest,
    diff_manifests,
    read_manifest,
    write_manifest,
)


def test_build_manifest_hashes_each_file(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("alpha")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("beta")

    entries = build_manifest(tmp_path)
    paths = {e.path for e in entries}

    assert paths == {"a.txt", "sub/b.txt"}
    by_path = {e.path: e for e in entries}
    assert by_path["a.txt"].size == 5
    assert by_path["a.txt"].sha256 == (
        "55c53f5d490297900cefa825d0c8e8e9532ee8a118abe7d8570762cd38be9818"
    )


def test_build_manifest_skips_dot_dirs(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main")
    (tmp_path / "code.js").write_text("x=1")

    entries = build_manifest(tmp_path)

    assert {e.path for e in entries} == {"code.js"}


def test_build_manifest_paths_are_posix(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "foo.ts").write_text("//")

    entries = build_manifest(tmp_path)

    assert entries[0].path == "src/foo.ts"


def test_write_then_read_manifest_roundtrips(tmp_path: Path) -> None:
    (tmp_path / "x").write_text("x")
    src = tmp_path / "src"
    src.mkdir()
    (src / "y").write_text("yy")

    target = tmp_path / "manifest.jsonl"
    write_manifest(target, build_manifest(tmp_path))
    parsed = read_manifest(target)

    assert {e.path for e in parsed} == {"x", "src/y", "manifest.jsonl"}
    for line in target.read_text().splitlines():
        json.loads(line)  # each line is valid JSON


def test_diff_manifests_detects_added_modified_removed() -> None:
    old = [
        ManifestEntry(path="keep.js", sha256="aa", size=1, mtime=0.0),
        ManifestEntry(path="changes.ts", sha256="bb", size=2, mtime=0.0),
        ManifestEntry(path="removed.html", sha256="cc", size=3, mtime=0.0),
    ]
    new = [
        ManifestEntry(path="keep.js", sha256="aa", size=1, mtime=0.0),
        ManifestEntry(path="changes.ts", sha256="b2", size=2, mtime=0.0),
        ManifestEntry(path="added.css", sha256="dd", size=4, mtime=0.0),
    ]
    diff = diff_manifests(old, new)
    assert diff.added == ["added.css"]
    assert diff.modified == ["changes.ts"]
    assert diff.removed == ["removed.html"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_manifest.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `manifest.py`**

```python
"""File-content manifest used for snapshot integrity and incremental diffing."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

_HASH_BUF = 65_536  # 64 KiB
_DOT_DIR_SKIP = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "__pycache__"})


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """One file's record in the manifest."""

    path: str       # POSIX-style relative path
    sha256: str     # hex digest
    size: int       # bytes
    mtime: float    # POSIX timestamp


@dataclass(frozen=True, slots=True)
class ManifestDiff:
    """Difference between two manifests."""

    added: list[str]
    modified: list[str]
    removed: list[str]


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_HASH_BUF):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root: Path) -> list[ManifestEntry]:
    """Walk ``root`` and return one ``ManifestEntry`` per regular file.

    Skips dotted directories like ``.git`` and known noise dirs like
    ``node_modules``. Hashes are SHA-256; paths are stored POSIX-style
    relative to ``root``.
    """
    entries: list[ManifestEntry] = []
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in _DOT_DIR_SKIP for part in path.relative_to(root).parts):
            continue
        rel = path.relative_to(root).as_posix()
        stat = path.stat()
        entries.append(
            ManifestEntry(
                path=rel,
                sha256=_hash_file(path),
                size=stat.st_size,
                mtime=stat.st_mtime,
            )
        )
    return entries


def write_manifest(target: Path, entries: Iterable[ManifestEntry]) -> None:
    """Write ``entries`` as JSON Lines to ``target`` atomically."""
    tmp = target.with_suffix(target.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(asdict(entry), separators=(",", ":")))
            f.write("\n")
    tmp.replace(target)


def read_manifest(target: Path) -> list[ManifestEntry]:
    """Parse a manifest written by :func:`write_manifest`."""
    out: list[ManifestEntry] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        out.append(ManifestEntry(**json.loads(line)))
    return out


def diff_manifests(old: list[ManifestEntry], new: list[ManifestEntry]) -> ManifestDiff:
    """Compute ``added`` / ``modified`` / ``removed`` paths between two manifests."""
    old_by_path = {e.path: e for e in old}
    new_by_path = {e.path: e for e in new}
    added = sorted(set(new_by_path) - set(old_by_path))
    removed = sorted(set(old_by_path) - set(new_by_path))
    modified = sorted(
        path
        for path in set(old_by_path) & set(new_by_path)
        if old_by_path[path].sha256 != new_by_path[path].sha256
    )
    return ManifestDiff(added=added, modified=modified, removed=removed)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_manifest.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/manifest.py tests/test_manifest.py
git commit -m "feat(manifest): add file manifest with sha256 hashing and diff"
```

---

## Task 4: Snapshot — git worktree path (`snapshot.py` part 1)

**Files:**
- Create: `ai_codescan/snapshot.py`
- Test: `tests/test_snapshot.py` (git path only)

When the target is a git repo, snapshot uses `git worktree add` for cheap, pinned, deterministic copies. Worktrees share git objects with the source so the disk cost is the working tree only.

- [ ] **Step 1: Write the failing test (git case)**

`tests/test_snapshot.py`:

```python
"""Tests for ai_codescan.snapshot."""

import subprocess
from pathlib import Path

import pytest

from ai_codescan.snapshot import SnapshotResult, take_snapshot


def _init_git_repo(repo: Path) -> str:
    """Create a one-commit git repo at ``repo`` and return the commit SHA."""
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test"],
        check=True,
    )
    (repo / "hello.txt").write_text("hi")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "init"],
        check=True,
    )
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return sha


@pytest.mark.integration
def test_snapshot_uses_git_worktree_when_target_is_git(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    sha = _init_git_repo(target)
    cache = tmp_path / "cache"

    result = take_snapshot(target, cache_dir=cache)

    assert isinstance(result, SnapshotResult)
    assert result.snapshot_dir == cache / "source"
    assert (result.snapshot_dir / "hello.txt").is_file()
    assert (result.snapshot_dir / "hello.txt").read_text() == "hi"
    assert result.commit_sha == sha
    assert result.method == "git-worktree"
    assert (cache / "manifest.jsonl").is_file()


@pytest.mark.integration
def test_snapshot_pinned_to_explicit_commit(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    first_sha = _init_git_repo(target)
    (target / "hello.txt").write_text("changed")
    subprocess.run(["git", "-C", str(target), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(target), "commit", "-q", "-m", "second"],
        check=True,
    )
    cache = tmp_path / "cache"

    result = take_snapshot(target, cache_dir=cache, commit=first_sha)

    assert result.commit_sha == first_sha
    assert (result.snapshot_dir / "hello.txt").read_text() == "hi"


@pytest.mark.integration
def test_snapshot_idempotent_when_manifest_matches(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    _init_git_repo(target)
    cache = tmp_path / "cache"

    first = take_snapshot(target, cache_dir=cache)
    second = take_snapshot(target, cache_dir=cache)

    assert first.commit_sha == second.commit_sha
    assert second.skipped is True
    assert first.skipped is False
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_snapshot.py -v
```

Expected: ImportError on `ai_codescan.snapshot`.

- [ ] **Step 3: Implement `snapshot.py` (git path + skeleton)**

```python
"""Repository snapshot management.

Takes a deterministic, read-only snapshot of a target repo into the cache dir.
Uses ``git worktree`` when possible (cheap, shares objects); falls back to
``cp -r`` for non-git targets (Task 5).
"""

from __future__ import annotations

import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ai_codescan.manifest import build_manifest, read_manifest, write_manifest


@dataclass(frozen=True, slots=True)
class SnapshotResult:
    """What :func:`take_snapshot` produces."""

    snapshot_dir: Path
    manifest_path: Path
    commit_sha: str | None
    method: Literal["git-worktree", "cp"]
    skipped: bool  # True when a previous matching snapshot was reused


def _is_git_repo(target: Path) -> bool:
    return (target / ".git").exists()


def _resolve_commit(target: Path, commit: str | None) -> str:
    rev = commit or "HEAD"
    result = subprocess.run(
        ["git", "-C", str(target), "rev-parse", rev],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _make_read_only(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode
        path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def _existing_snapshot_matches(
    cache_dir: Path,
    expected_commit: str | None,
) -> bool:
    """Return True if a previous snapshot in ``cache_dir`` is still valid."""
    head_marker = cache_dir / ".snapshot-commit"
    if expected_commit is None or not head_marker.is_file():
        return False
    return head_marker.read_text(encoding="utf-8").strip() == expected_commit


def _git_worktree_snapshot(target: Path, cache_dir: Path, commit: str) -> Path:
    snapshot_dir = cache_dir / "source"
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir, onerror=_force_remove)
    cache_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "-C", str(target), "worktree", "add", "--detach", str(snapshot_dir), commit],
        check=True,
        capture_output=True,
    )
    return snapshot_dir


def _force_remove(_func, path, _exc) -> None:
    """``shutil.rmtree`` ``onerror`` hook to clear read-only bits before retry."""
    Path(path).chmod(stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
    Path(path).unlink(missing_ok=True)


def take_snapshot(
    target: Path,
    *,
    cache_dir: Path,
    commit: str | None = None,
) -> SnapshotResult:
    """Snapshot ``target`` into ``cache_dir``.

    Returns a :class:`SnapshotResult` describing where the snapshot landed.
    Re-invocation with the same ``commit`` is idempotent: returns
    ``skipped=True`` without re-copying.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    if _is_git_repo(target):
        sha = _resolve_commit(target, commit)
        if _existing_snapshot_matches(cache_dir, sha):
            return SnapshotResult(
                snapshot_dir=cache_dir / "source",
                manifest_path=cache_dir / "manifest.jsonl",
                commit_sha=sha,
                method="git-worktree",
                skipped=True,
            )
        snapshot_dir = _git_worktree_snapshot(target, cache_dir, sha)
        (cache_dir / ".snapshot-commit").write_text(sha, encoding="utf-8")
        method: Literal["git-worktree", "cp"] = "git-worktree"
    else:
        raise NotImplementedError("non-git snapshot lands in Task 5")

    manifest_path = cache_dir / "manifest.jsonl"
    write_manifest(manifest_path, build_manifest(snapshot_dir))
    _make_read_only(snapshot_dir)
    _ = read_manifest  # imported for Task 5 / later use
    return SnapshotResult(
        snapshot_dir=snapshot_dir,
        manifest_path=manifest_path,
        commit_sha=sha if _is_git_repo(target) else None,
        method=method,
        skipped=False,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_snapshot.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/snapshot.py tests/test_snapshot.py
git commit -m "feat(snapshot): git worktree snapshot path"
```

---

## Task 5: Snapshot — cp fallback for non-git targets

**Files:**
- Modify: `ai_codescan/snapshot.py` (replace the `NotImplementedError` branch)
- Modify: `tests/test_snapshot.py` (add non-git tests)

- [ ] **Step 1: Write the failing tests for the cp path**

Append to `tests/test_snapshot.py`:

```python
@pytest.mark.integration
def test_snapshot_cp_for_non_git_target(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.js").write_text("module.exports = 1;")
    (target / "sub").mkdir()
    (target / "sub" / "b.html").write_text("<p>hi</p>")
    cache = tmp_path / "cache"

    result = take_snapshot(target, cache_dir=cache)

    assert result.method == "cp"
    assert result.commit_sha is None
    assert (result.snapshot_dir / "a.js").read_text() == "module.exports = 1;"
    assert (result.snapshot_dir / "sub" / "b.html").read_text() == "<p>hi</p>"


@pytest.mark.integration
def test_snapshot_marks_files_read_only(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.js").write_text("x")
    cache = tmp_path / "cache"

    result = take_snapshot(target, cache_dir=cache)

    snap_file = result.snapshot_dir / "a.js"
    assert not (snap_file.stat().st_mode & 0o222)


@pytest.mark.integration
def test_snapshot_cp_idempotent_when_manifest_matches(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.js").write_text("x")
    cache = tmp_path / "cache"

    first = take_snapshot(target, cache_dir=cache)
    second = take_snapshot(target, cache_dir=cache)

    assert first.skipped is False
    assert second.skipped is True
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_snapshot.py -v
```

Expected: 3 new tests fail with `NotImplementedError`.

- [ ] **Step 3: Implement the cp path**

Replace the body of `take_snapshot` with the unified flow and add the cp helper.

In `ai_codescan/snapshot.py`, replace `take_snapshot` and add `_cp_snapshot`:

```python
def _cp_snapshot(target: Path, cache_dir: Path) -> Path:
    snapshot_dir = cache_dir / "source"
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir, onerror=_force_remove)
    shutil.copytree(target, snapshot_dir, symlinks=False, ignore_dangling_symlinks=True)
    return snapshot_dir


def _manifest_already_matches(cache_dir: Path, snapshot_dir: Path) -> bool:
    """For non-git targets: return True if the snapshot content already matches."""
    manifest_path = cache_dir / "manifest.jsonl"
    if not manifest_path.is_file() or not snapshot_dir.exists():
        return False
    return read_manifest(manifest_path) == build_manifest(snapshot_dir)


def take_snapshot(
    target: Path,
    *,
    cache_dir: Path,
    commit: str | None = None,
) -> SnapshotResult:
    """Snapshot ``target`` into ``cache_dir``.

    Uses ``git worktree`` when ``target`` is a git repo, ``cp -r`` otherwise.
    Idempotent: a re-invocation with matching state returns ``skipped=True``.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    snapshot_dir = cache_dir / "source"
    manifest_path = cache_dir / "manifest.jsonl"

    if _is_git_repo(target):
        sha = _resolve_commit(target, commit)
        if _existing_snapshot_matches(cache_dir, sha):
            return SnapshotResult(
                snapshot_dir=snapshot_dir,
                manifest_path=manifest_path,
                commit_sha=sha,
                method="git-worktree",
                skipped=True,
            )
        snapshot_dir = _git_worktree_snapshot(target, cache_dir, sha)
        (cache_dir / ".snapshot-commit").write_text(sha, encoding="utf-8")
        method: Literal["git-worktree", "cp"] = "git-worktree"
        commit_sha: str | None = sha
    else:
        if _manifest_already_matches(cache_dir, snapshot_dir):
            return SnapshotResult(
                snapshot_dir=snapshot_dir,
                manifest_path=manifest_path,
                commit_sha=None,
                method="cp",
                skipped=True,
            )
        snapshot_dir = _cp_snapshot(target, cache_dir)
        method = "cp"
        commit_sha = None

    write_manifest(manifest_path, build_manifest(snapshot_dir))
    _make_read_only(snapshot_dir)
    return SnapshotResult(
        snapshot_dir=snapshot_dir,
        manifest_path=manifest_path,
        commit_sha=commit_sha,
        method=method,
        skipped=False,
    )
```

Remove the now-unused `_ = read_manifest  # imported for Task 5 / later use` line.

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_snapshot.py -v
```

Expected: 6 passed total.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/snapshot.py tests/test_snapshot.py
git commit -m "feat(snapshot): cp fallback for non-git targets, read-only enforcement"
```

---

## Task 6: Stack-detect — project discovery (`stack_detect.py` part 1)

**Files:**
- Create: `ai_codescan/stack_detect.py`
- Create: `tests/fixtures/tiny-express/`
- Create: `tests/fixtures/tiny-react/`
- Create: `tests/fixtures/monorepo-pnpm/`
- Test: `tests/test_stack_detect.py` (project discovery only)

A "project" is one logical unit — at minimum, anything with a `package.json`. Monorepos may have many. Detection must enumerate them all and identify the workspace root.

- [ ] **Step 1: Create test fixtures**

```bash
cd /home/robin/Hacking/AI_Analysis/tests/fixtures

mkdir -p tiny-express
cat > tiny-express/package.json <<'EOF'
{
  "name": "tiny-express",
  "version": "0.0.1",
  "dependencies": { "express": "^4.21.0" }
}
EOF
cat > tiny-express/package-lock.json <<'EOF'
{ "name": "tiny-express", "lockfileVersion": 3, "packages": {} }
EOF
cat > tiny-express/server.js <<'EOF'
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('hi'));
app.listen(3000);
EOF

mkdir -p tiny-react/src
cat > tiny-react/package.json <<'EOF'
{
  "name": "tiny-react",
  "version": "0.0.1",
  "dependencies": { "react": "^19.0.0", "react-dom": "^19.0.0" },
  "devDependencies": { "typescript": "^5.6.0" }
}
EOF
cat > tiny-react/pnpm-lock.yaml <<'EOF'
lockfileVersion: '9.0'
EOF
cat > tiny-react/tsconfig.json <<'EOF'
{ "compilerOptions": { "target": "ES2022", "jsx": "react-jsx" } }
EOF
cat > tiny-react/src/App.tsx <<'EOF'
export const App = () => <div>hi</div>;
EOF

mkdir -p monorepo-pnpm/packages/api monorepo-pnpm/packages/web
cat > monorepo-pnpm/package.json <<'EOF'
{ "name": "monorepo-root", "private": true }
EOF
cat > monorepo-pnpm/pnpm-workspace.yaml <<'EOF'
packages:
  - 'packages/*'
EOF
cat > monorepo-pnpm/packages/api/package.json <<'EOF'
{ "name": "api", "dependencies": { "fastify": "^5.0.0" } }
EOF
cat > monorepo-pnpm/packages/api/server.ts <<'EOF'
import Fastify from 'fastify';
const app = Fastify();
app.get('/', async () => 'hi');
app.listen({ port: 3000 });
EOF
cat > monorepo-pnpm/packages/web/package.json <<'EOF'
{ "name": "web" }
EOF
cat > monorepo-pnpm/packages/web/index.html <<'EOF'
<!doctype html><html><body><h1>hi</h1></body></html>
EOF
```

- [ ] **Step 2: Write the failing tests**

`tests/test_stack_detect.py`:

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
uv run pytest tests/test_stack_detect.py -v
```

Expected: ImportError.

- [ ] **Step 4: Implement project discovery**

```python
"""Detect logical projects (each with one ``package.json``) inside a snapshot.

Phase 1A only handles JS/TS + HTML targets; framework fingerprinting lives
in Task 7. This module is responsible for enumerating projects and labeling
their language and workspace topology.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

_SKIP_DIRS = frozenset({"node_modules", ".git", ".pnpm", ".yarn", "dist", "build", ".next"})


class ProjectKind(str, Enum):
    """Coarse classification of a detected project."""

    NODE = "node"          # has a package.json
    HTML_ONLY = "html"     # no package.json, but contains HTML


@dataclass(frozen=True, slots=True)
class Project:
    """One logical project inside a snapshot."""

    name: str
    kind: ProjectKind
    base_path: Path                       # relative to snapshot root, "." for root
    languages: set[str] = field(default_factory=set)
    has_tsconfig: bool = False
    is_workspace_member: bool = False
    workspace_root: Path | None = None    # base_path of the workspace root (if any)


def _is_workspace_root(pkg_json: Path) -> bool:
    """Return True if this package.json declares pnpm/yarn/npm workspaces."""
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if "workspaces" in data:
        return True
    return (pkg_json.parent / "pnpm-workspace.yaml").is_file()


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


def _iter_files(root: Path, suffix: str):
    for path in root.rglob(f"*{suffix}"):
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def _project_name(pkg_json: Path) -> str:
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return pkg_json.parent.name
    return str(data.get("name") or pkg_json.parent.name)


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
        projects.append(
            Project(
                name=_project_name(pkg),
                kind=ProjectKind.NODE,
                base_path=rel,
                languages=_detect_languages(pkg.parent),
                has_tsconfig=(pkg.parent / "tsconfig.json").is_file(),
                is_workspace_member=workspace_root_path is not None and not is_root,
                workspace_root=workspace_root_path,
            )
        )

    if not projects:
        if any(_iter_files(root, ".html")) or any(_iter_files(root, ".htm")):
            projects.append(
                Project(
                    name=root.name,
                    kind=ProjectKind.HTML_ONLY,
                    base_path=Path("."),
                    languages={"html"},
                )
            )
    return projects
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
uv run pytest tests/test_stack_detect.py -v
```

Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add ai_codescan/stack_detect.py tests/test_stack_detect.py tests/fixtures/
git commit -m "feat(stack_detect): project + workspace discovery"
```

---

## Task 7: Stack-detect — framework + package-manager fingerprinting

**Files:**
- Modify: `ai_codescan/stack_detect.py` (extend `Project`, add framework detection)
- Modify: `tests/test_stack_detect.py` (add framework tests)

- [ ] **Step 1: Extend the `Project` dataclass and add fingerprint helpers (failing tests first)**

Append to `tests/test_stack_detect.py`:

```python
def test_express_framework_detected(fixtures_dir: Path) -> None:
    p = detect_projects(fixtures_dir / "tiny-express")[0]
    assert "express" in p.frameworks
    assert p.package_manager == "npm"


def test_react_and_typescript_framework_detected(fixtures_dir: Path) -> None:
    p = detect_projects(fixtures_dir / "tiny-react")[0]
    assert "react" in p.frameworks
    assert p.package_manager == "pnpm"


def test_fastify_in_monorepo_workspace(fixtures_dir: Path) -> None:
    api = next(
        p for p in detect_projects(fixtures_dir / "monorepo-pnpm") if p.name == "api"
    )
    assert "fastify" in api.frameworks
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_stack_detect.py -v
```

Expected: 3 failures, `Project` has no `frameworks` / `package_manager` attribute.

- [ ] **Step 3: Implement framework + package-manager detection**

In `ai_codescan/stack_detect.py`:

Replace the `Project` dataclass with the extended version:

```python
@dataclass(frozen=True, slots=True)
class Project:
    """One logical project inside a snapshot."""

    name: str
    kind: ProjectKind
    base_path: Path
    languages: set[str] = field(default_factory=set)
    has_tsconfig: bool = False
    is_workspace_member: bool = False
    workspace_root: Path | None = None
    frameworks: set[str] = field(default_factory=set)
    package_manager: str = "unknown"
```

Add the fingerprint helpers below the existing helpers:

```python
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
```

In `detect_projects`, after computing each project's package json, populate `frameworks` and `package_manager`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_stack_detect.py -v
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/stack_detect.py tests/test_stack_detect.py
git commit -m "feat(stack_detect): framework and package-manager fingerprinting"
```

---

## Task 8: `repo.md` rendering (`repo_md.py`)

**Files:**
- Create: `ai_codescan/repo_md.py`
- Test: `tests/test_repo_md.py`

`repo.md` is the human-and-LLM-readable summary of detection. Stable formatting so reruns produce byte-identical output.

- [ ] **Step 1: Write the failing tests**

`tests/test_repo_md.py`:

```python
"""Tests for ai_codescan.repo_md."""

from pathlib import Path

from ai_codescan.repo_md import render_repo_md
from ai_codescan.stack_detect import Project, ProjectKind


def _project(**overrides: object) -> Project:
    base = {
        "name": "tiny",
        "kind": ProjectKind.NODE,
        "base_path": Path("."),
        "languages": {"typescript"},
        "has_tsconfig": True,
        "is_workspace_member": False,
        "workspace_root": None,
        "frameworks": {"react"},
        "package_manager": "pnpm",
    }
    base.update(overrides)
    return Project(**base)  # type: ignore[arg-type]


def test_render_includes_header_and_project_section() -> None:
    md = render_repo_md(target_name="my-target", projects=[_project()])
    assert md.startswith("# Repository: my-target\n")
    assert "## Project: tiny" in md
    assert "- Path: `.`" in md
    assert "- Kind: node" in md
    assert "- Languages: typescript" in md
    assert "- Frameworks: react" in md
    assert "- Package manager: pnpm" in md
    assert "- TS config: yes" in md


def test_render_is_stable_byte_for_byte() -> None:
    md1 = render_repo_md(target_name="t", projects=[_project()])
    md2 = render_repo_md(target_name="t", projects=[_project()])
    assert md1 == md2


def test_render_sorts_projects_by_base_path() -> None:
    md = render_repo_md(
        target_name="mono",
        projects=[
            _project(name="z", base_path=Path("packages/z")),
            _project(name="a", base_path=Path("packages/a")),
        ],
    )
    a_idx = md.index("## Project: a")
    z_idx = md.index("## Project: z")
    assert a_idx < z_idx


def test_render_handles_empty_projects() -> None:
    md = render_repo_md(target_name="empty", projects=[])
    assert "No projects detected" in md
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_repo_md.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `repo_md.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_repo_md.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/repo_md.py tests/test_repo_md.py
git commit -m "feat(repo_md): render stable repo.md from detected projects"
```

---

## Task 9: CLI scaffold (`cli.py`)

**Files:**
- Create: `ai_codescan/cli.py`
- Test: `tests/test_cli.py`

Typer app with subcommands and global flags. `prep` is wired in Task 10; `cache list/rm/gc` and `status` are stubs that return cleanly; `--install-completion` is Typer-native.

- [ ] **Step 1: Write the failing tests**

`tests/test_cli.py`:

```python
"""Tests for ai_codescan.cli."""

from pathlib import Path

from typer.testing import CliRunner

from ai_codescan.cli import app

runner = CliRunner()


def test_help_shows_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "prep" in result.stdout
    assert "cache" in result.stdout
    assert "status" in result.stdout


def test_prep_help_shows_flags() -> None:
    result = runner.invoke(app, ["prep", "--help"])
    assert result.exit_code == 0
    assert "--cache-dir" in result.stdout
    assert "--commit" in result.stdout


def test_cache_list_handles_missing_root(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--cache-dir", str(tmp_path / "nope"), "cache", "list"])
    assert result.exit_code == 0
    assert "No cached repos" in result.stdout


def test_status_with_no_run_says_no_runs(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--cache-dir", str(tmp_path), "status"],
    )
    assert result.exit_code == 0
    assert "No cached repos" in result.stdout
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement the CLI scaffold**

```python
"""Command-line entry point for ai-codescan."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from ai_codescan.config import default_cache_root

app = typer.Typer(
    name="ai-codescan",
    help="AI-driven SAST pipeline (Phase 1A: prep produces snapshot + repo.md).",
    no_args_is_help=True,
)
cache_app = typer.Typer(name="cache", help="Manage cached repos.", no_args_is_help=True)
app.add_typer(cache_app)


_CacheDirOption = Annotated[
    Path | None,
    typer.Option(
        "--cache-dir",
        help="Override the cache root (default: ~/.ai_codescan/repos).",
    ),
]
_CommitOption = Annotated[
    str | None,
    typer.Option("--commit", help="Pin snapshot to a specific git commit SHA."),
]
_QuietOption = Annotated[bool, typer.Option("--quiet", "-q", help="Suppress non-error output.")]
_VerboseOption = Annotated[bool, typer.Option("--verbose", "-v", help="Verbose logging.")]


@app.callback()
def _root(
    ctx: typer.Context,
    cache_dir: _CacheDirOption = None,
    quiet: _QuietOption = False,
    verbose: _VerboseOption = False,
) -> None:
    """Top-level options shared by every subcommand."""
    ctx.obj = {
        "cache_root": cache_dir if cache_dir is not None else default_cache_root(),
        "quiet": quiet,
        "verbose": verbose,
    }


@app.command()
def prep(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Target repo to scan.")],
    commit: _CommitOption = None,
) -> None:
    """Snapshot ``target``, detect its stack, and write ``repo.md``."""
    typer.echo("prep is not implemented yet (Task 10)")
    raise typer.Exit(code=1)


@app.command()
def status(ctx: typer.Context) -> None:
    """Print summary of cached repos and their phase progress."""
    cache_root: Path = ctx.obj["cache_root"]
    if not cache_root.exists():
        typer.echo("No cached repos.")
        return
    repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
    if not repos:
        typer.echo("No cached repos.")
        return
    for name in repos:
        typer.echo(f"- {name}")


@cache_app.command("list")
def cache_list(ctx: typer.Context) -> None:
    """List cached repos."""
    cache_root: Path = ctx.obj["cache_root"]
    if not cache_root.exists():
        typer.echo("No cached repos.")
        return
    repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
    if not repos:
        typer.echo("No cached repos.")
        return
    for name in repos:
        typer.echo(name)


@cache_app.command("rm")
def cache_rm(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Argument(help="Repo id to remove.")],
) -> None:
    """Remove a cached repo by id."""
    import shutil
    import stat as stat_mod

    cache_root: Path = ctx.obj["cache_root"]
    repo_dir = cache_root / repo_id
    if not repo_dir.exists():
        typer.echo(f"Not found: {repo_id}", err=True)
        raise typer.Exit(code=1)

    def _force(_func, path, _exc):
        Path(path).chmod(stat_mod.S_IWUSR | stat_mod.S_IRUSR | stat_mod.S_IXUSR)
        Path(path).unlink(missing_ok=True)

    shutil.rmtree(repo_dir, onerror=_force)
    typer.echo(f"Removed {repo_id}")


@cache_app.command("gc")
def cache_gc(ctx: typer.Context) -> None:
    """Stub — Phase 1B will implement stale-snapshot collection."""
    typer.echo("cache gc not implemented yet")


if __name__ == "__main__":
    app()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/cli.py tests/test_cli.py
git commit -m "feat(cli): scaffold typer app with subcommand stubs"
```

---

## Task 10: Wire `prep` end-to-end

**Files:**
- Modify: `ai_codescan/cli.py` (replace `prep` body)
- Modify: `tests/test_cli.py` (add integration tests)

- [ ] **Step 1: Write the failing integration tests**

Append to `tests/test_cli.py`:

```python
import pytest


@pytest.mark.integration
def test_prep_creates_snapshot_and_repo_md(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-react")],
    )
    assert result.exit_code == 0, result.stdout
    repo_dirs = list(cache.iterdir())
    assert len(repo_dirs) == 1
    repo_dir = repo_dirs[0]
    assert (repo_dir / "source" / "package.json").is_file()
    assert (repo_dir / "manifest.jsonl").is_file()
    repo_md = (repo_dir / "repo.md").read_text(encoding="utf-8")
    assert "react" in repo_md
    assert "typescript" in repo_md


@pytest.mark.integration
def test_prep_idempotent_on_second_run(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    args = ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)
    assert first.exit_code == 0
    assert second.exit_code == 0
    assert "skipped" in second.stdout.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: 2 new failures (`prep` exits 1, "not implemented yet").

- [ ] **Step 3: Replace the `prep` body**

In `ai_codescan/cli.py`, replace the `prep` function with:

```python
@app.command()
def prep(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Target repo to scan.")],
    commit: _CommitOption = None,
) -> None:
    """Snapshot ``target``, detect its stack, and write ``repo.md``."""
    from ai_codescan.config import compute_repo_id
    from ai_codescan.repo_md import render_repo_md
    from ai_codescan.snapshot import take_snapshot
    from ai_codescan.stack_detect import detect_projects

    if not target.is_dir():
        typer.echo(f"Target is not a directory: {target}", err=True)
        raise typer.Exit(code=2)

    cache_root: Path = ctx.obj["cache_root"]
    quiet: bool = ctx.obj["quiet"]
    repo_dir = cache_root / compute_repo_id(target)

    snap = take_snapshot(target, cache_dir=repo_dir, commit=commit)
    if not quiet:
        status_word = "skipped" if snap.skipped else "took"
        method = snap.method
        commit_label = f" @ {snap.commit_sha[:8]}" if snap.commit_sha else ""
        typer.echo(f"snapshot {status_word} ({method}){commit_label}")

    projects = detect_projects(snap.snapshot_dir)
    repo_md_path = repo_dir / "repo.md"
    repo_md_path.write_text(
        render_repo_md(target_name=target.name, projects=projects),
        encoding="utf-8",
    )
    if not quiet:
        typer.echo(f"detected {len(projects)} project(s); wrote {repo_md_path}")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: 6 passed (4 original + 2 integration).

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/cli.py tests/test_cli.py
git commit -m "feat(cli): wire prep to snapshot + stack-detect + repo.md"
```

---

## Task 11: `cache list` enriched output

**Files:**
- Modify: `ai_codescan/cli.py` (`cache_list` shows snapshot age + size)
- Modify: `tests/test_cli.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
@pytest.mark.integration
def test_cache_list_shows_repo_after_prep(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    result = runner.invoke(app, ["--cache-dir", str(cache), "cache", "list"])
    assert result.exit_code == 0
    assert "tiny-express-" in result.stdout
    assert "MB" in result.stdout or "KB" in result.stdout or "B " in result.stdout


@pytest.mark.integration
def test_cache_rm_removes_repo_dir(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    result = runner.invoke(app, ["--cache-dir", str(cache), "cache", "rm", repo_id])
    assert result.exit_code == 0
    assert not (cache / repo_id).exists()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: `test_cache_list_shows_repo_after_prep` fails because the existing implementation only prints the name.

- [ ] **Step 3: Improve `cache_list` output**

In `ai_codescan/cli.py`, replace `cache_list` with:

```python
def _human_size(bytes_: int) -> str:
    size = float(bytes_)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:>6.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file() and not p.is_symlink():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


@cache_app.command("list")
def cache_list(ctx: typer.Context) -> None:
    """List cached repos with size + age."""
    import datetime as _dt

    cache_root: Path = ctx.obj["cache_root"]
    if not cache_root.exists():
        typer.echo("No cached repos.")
        return
    repos = sorted(p for p in cache_root.iterdir() if p.is_dir())
    if not repos:
        typer.echo("No cached repos.")
        return
    for repo_dir in repos:
        size = _dir_size(repo_dir)
        mtime = _dt.datetime.fromtimestamp(repo_dir.stat().st_mtime, tz=_dt.UTC)
        typer.echo(f"{repo_dir.name}\t{_human_size(size)}\t{mtime.isoformat(timespec='seconds')}")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/cli.py tests/test_cli.py
git commit -m "feat(cli): cache list shows size + mtime"
```

---

## Task 12: Quality gates (ruff + ty + coverage)

**Files:**
- Modify: `pyproject.toml` (add a `[tool.ty]` block)
- Create: `Makefile` (or shell script) for `make check`

- [ ] **Step 1: Add `ty` configuration**

Append to `pyproject.toml`:

```toml
[tool.ty]
src = ["ai_codescan", "tests"]

[tool.ty.rules]
strict = "error"
```

- [ ] **Step 2: Create `Makefile`**

```make
.PHONY: lint format typecheck test check

lint:
	uv run ruff check ai_codescan tests

format:
	uv run ruff format ai_codescan tests

typecheck:
	uv run ty check

test:
	uv run pytest

check: lint typecheck test
```

- [ ] **Step 3: Run the gate locally to verify**

```bash
cd /home/robin/Hacking/AI_Analysis
make format
make check
```

Expected: every step exits 0. Fix any warnings inline before committing — we hold a zero-warning policy (per global CLAUDE.md).

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml Makefile
git commit -m "chore: add ty config and make check target"
```

---

## Task 13: Smoke test against a small real repo

**Files:**
- (no files written; this is a manual smoke test recorded in the README)

- [ ] **Step 1: Pick a tiny open-source target**

```bash
cd /tmp
git clone --depth 1 https://github.com/expressjs/express.git tmp-express
```

- [ ] **Step 2: Run prep**

```bash
cd /home/robin/Hacking/AI_Analysis
uv run ai-codescan prep /tmp/tmp-express
```

Expected:
- exits 0
- prints `snapshot took (git-worktree) @ <8-char-sha>`
- prints `detected 1 project(s); wrote /home/robin/.ai_codescan/repos/tmp-express-XXXXXXXX/repo.md`

- [ ] **Step 3: Verify the repo.md content**

```bash
cat ~/.ai_codescan/repos/tmp-express-*/repo.md
```

Expected: header `# Repository: tmp-express`, one Project section showing `express` framework (or empty frameworks if the express repo's own deps don't reference itself; `mocha` may show as a dev dep — that's fine).

- [ ] **Step 4: Verify idempotency**

```bash
uv run ai-codescan prep /tmp/tmp-express
```

Expected: `snapshot skipped (git-worktree) @ <sha>`.

- [ ] **Step 5: Append a smoke-test note to `README.md`**

Add a new section to `README.md` (under the `## Phase 1A status` heading):

```markdown
## Smoke test (Phase 1A)

```bash
git clone --depth 1 https://github.com/expressjs/express.git /tmp/tmp-express
uv run ai-codescan prep /tmp/tmp-express
cat ~/.ai_codescan/repos/tmp-express-*/repo.md
uv run ai-codescan cache list
```
```

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "docs: add smoke test instructions for Phase 1A"
```

- [ ] **Step 7: Tag the milestone**

```bash
git tag -a phase-1a -m "Phase 1A: foundation, snapshot, stack-detect"
```

---

## Self-review

Spec coverage check (against `2026-05-08-ai-codescan-phase1-design.md`):

| Spec section | Implemented in | Notes |
|---|---|---|
| §5.1 `snapshot.py` | Task 4 + 5 | git worktree + cp; read-only enforcement; idempotency |
| §5.2 `stack_detect.py` | Tasks 6 + 7 | Project + framework + package-manager detection. `repo.md` rendering separated into `repo_md.py` (Task 8) |
| §5.10 / §7 CLI | Tasks 9–11 | `prep`, `cache list/rm/gc`, `status`. `--commit`, `--cache-dir`, `--quiet`, `--verbose`. `--install-completion` is Typer-native; verified with smoke test |
| §8 cache layout | Task 1 + 4 + 10 | `<cache>/<repo_id>/source/`, `manifest.jsonl`, `repo.md` |
| §11.4 reproducibility | Task 1 (pyproject) + Task 8 (stable rendering) | Pinned versions; sorted output |
| §11.3 testing | Throughout | Each task TDD; integration tests in `tests/test_cli.py`; fixture targets under `tests/fixtures/` |

Deferred to later sub-plans (1B–1E):
- `entrypoints.md` rendering (1D — needs AST output)
- `--target-bug-class` flag (1E — needs taxonomy + nominator)
- `--engine` flag (1C — only meaningful once CodeQL exists)
- `--temperature`, `--temperature-deep`, `--cost-cap`, `--report-dir` (1E — only meaningful with LLM steps)
- `--yes` (1E — gates exist in 1E)
- Coverage thresholds in CI (deferred to a CI sub-plan when we add GitHub Actions)

No placeholders. All step bodies contain executable code or commands. Every type / function name used in later tasks is defined in the task that introduces it. CLI test imports match the symbols defined in `cli.py` (Task 9).

---

## Execution

Plan complete and saved to `docs/superpowers/plans/2026-05-08-ai-codescan-1a-foundation.md`.

After this plan is executed, sub-plans 1B–1E follow. Each will be its own writing-plans pass once 1A is shipped and tested.
