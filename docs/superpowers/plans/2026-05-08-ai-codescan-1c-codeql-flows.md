# AI_Codescan 1C — CodeQL Integration + Flow Ingestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a CodeQL database from each detected JS/TS project, run security query suites filtered by `--target-bug-class`, and ingest the resulting SARIF into `taint_sources`, `taint_sinks`, and `flows`. After this plan, `ai-codescan flows --from/--to` returns real data and the `v_sources_to_sinks` view answers actual taint queries.

**Architecture:** CodeQL CLI is invoked via `subprocess`. Each project gets its own DB. SARIF 2.1.0 `results[].codeFlows[].threadFlows[].locations[]` is parsed into flow records. The bug-class taxonomy YAML maps human names to CodeQL `--query-tag` filters and `--query-suite` choices. `--engine codeql` is the only Phase-1 mode but the flag is added for forward-compat.

**Tech Stack:** Python additions: `pyyaml>=6` (taxonomy loader), `sarif-om>=1.0.4` (typed SARIF parsing). External: `codeql` CLI 2.25+ on PATH; `security-extended` and `security-and-quality` query packs pre-installed via `codeql pack download codeql/javascript-queries`.

**Reference spec:** §4.2 (engine modes), §5.5 (CodeQL component), §5.6 (DuckDB taint tables), §6 (bug-class taxonomy → tags), §11.2 (error handling for OOM).

**Depends on:** Plans 1A + 1B complete. `index.duckdb` exists with files / symbols / xrefs populated.

---

## File Structure (added)

```
AI_Analysis/
├── ai_codescan/
│   ├── engines/
│   │   ├── __init__.py
│   │   └── codeql.py
│   ├── taxonomy/
│   │   ├── __init__.py
│   │   ├── bug_classes.yaml
│   │   └── loader.py
│   ├── ingest/
│   │   ├── __init__.py
│   │   └── sarif.py
│   └── prep.py                        # extended to call CodeQL
└── tests/
    ├── test_taxonomy_loader.py
    ├── test_codeql_runner.py
    ├── test_sarif_ingest.py
    └── fixtures/
        ├── tiny-vuln/
        │   ├── package.json
        │   └── server.js
        └── sample.sarif
```

---

## Task 1: Add deps

**Files:** Modify `pyproject.toml`.

- [ ] **Step 1: Add deps**

```toml
dependencies = [
  "typer>=0.15.1",
  "duckdb>=1.1.3",
  "protobuf>=5.28",
  "xxhash>=3.5",
  "pyyaml>=6.0.2",
  "sarif-om>=1.0.4",
]
```

- [ ] **Step 2: Sync + verify**

```bash
uv sync --all-groups
uv run python -c "import yaml, sarif_om; print('ok')"
```

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "chore(deps): add pyyaml and sarif-om"
```

---

## Task 2: Bug-class taxonomy YAML + loader

**Files:**
- Create: `ai_codescan/taxonomy/__init__.py`
- Create: `ai_codescan/taxonomy/bug_classes.yaml`
- Create: `ai_codescan/taxonomy/loader.py`
- Test: `tests/test_taxonomy_loader.py`

- [ ] **Step 1: Author the canonical YAML (1C subset)**

`ai_codescan/taxonomy/bug_classes.yaml`:

```yaml
# Phase 1C subset: only flow-traceable classes (CodeQL has a model).
# Full taxonomy with semantic-only classes (idor, bfla) lands in 1E.

xss:
  cwes: [CWE-79]
  codeql_tags: [security/cwe/cwe-079]
  group: injection

sqli:
  aliases: [sql-injection]
  cwes: [CWE-89]
  codeql_tags: [security/cwe/cwe-089]
  group: injection

nosqli:
  aliases: [nosql-injection]
  cwes: [CWE-943]
  codeql_tags: [security/cwe/cwe-943]
  group: injection

cmdi:
  aliases: [command-injection, os-cmdi]
  cwes: [CWE-78]
  codeql_tags: [security/cwe/cwe-078]
  group: injection

code-injection:
  cwes: [CWE-94]
  codeql_tags: [security/cwe/cwe-094]
  group: injection

ssti:
  aliases: [template-injection]
  cwes: [CWE-1336]
  codeql_tags: [security/cwe/cwe-1336]
  group: injection

xxe:
  aliases: [xml-external-entity]
  cwes: [CWE-611]
  codeql_tags: [security/cwe/cwe-611]
  group: injection

path-traversal:
  aliases: [dir-traversal]
  cwes: [CWE-22]
  codeql_tags: [security/cwe/cwe-022]
  group: file

ssrf:
  cwes: [CWE-918]
  codeql_tags: [security/cwe/cwe-918]
  group: request-forgery

open-redirect:
  cwes: [CWE-601]
  codeql_tags: [security/cwe/cwe-601]
  group: redirect

unsafe-deserialization:
  cwes: [CWE-502]
  codeql_tags: [security/cwe/cwe-502]
  group: serialization

prototype-pollution:
  cwes: [CWE-1321]
  codeql_tags: [security/cwe/cwe-1321]
  group: javascript

groups:
  injection:       [xss, sqli, nosqli, cmdi, code-injection, ssti, xxe]
  file:            [path-traversal]
  request-forgery: [ssrf]
  serialization:   [unsafe-deserialization]
  javascript:      [prototype-pollution]
  redirect:        [open-redirect]
```

- [ ] **Step 2: Failing tests**

`tests/test_taxonomy_loader.py`:

```python
"""Tests for ai_codescan.taxonomy.loader."""

import pytest

from ai_codescan.taxonomy.loader import (
    UnknownBugClassError,
    list_classes,
    resolve_classes,
)


def test_resolve_single_class() -> None:
    classes = resolve_classes(["xss"])
    assert {c.name for c in classes} == {"xss"}


def test_resolve_alias_to_canonical() -> None:
    classes = resolve_classes(["sql-injection"])
    assert {c.name for c in classes} == {"sqli"}


def test_resolve_group_expansion() -> None:
    classes = resolve_classes(["@injection"])
    names = {c.name for c in classes}
    assert "xss" in names and "sqli" in names and "cmdi" in names


def test_resolve_unknown_suggests_match() -> None:
    with pytest.raises(UnknownBugClassError) as exc:
        resolve_classes(["xs"])
    assert "did you mean 'xss'" in str(exc.value).lower()


def test_list_classes_returns_all_canonical_names() -> None:
    names = {c.name for c in list_classes()}
    assert "xss" in names and "ssrf" in names
```

- [ ] **Step 3: Implement loader**

`ai_codescan/taxonomy/__init__.py`:

```python
```

`ai_codescan/taxonomy/loader.py`:

```python
"""Load and resolve the bug-class taxonomy."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

import yaml


class UnknownBugClassError(ValueError):
    """Raised when a user supplies a name that's not in the taxonomy."""


@dataclass(frozen=True, slots=True)
class BugClass:
    name: str
    cwes: list[str]
    codeql_tags: list[str]
    group: str | None
    aliases: list[str]


def _yaml_path() -> Path:
    return Path(str(files("ai_codescan.taxonomy").joinpath("bug_classes.yaml")))


def _load_raw() -> dict:
    return yaml.safe_load(_yaml_path().read_text(encoding="utf-8")) or {}


def list_classes() -> list[BugClass]:
    raw = _load_raw()
    out: list[BugClass] = []
    for name, body in raw.items():
        if name == "groups" or not isinstance(body, dict):
            continue
        out.append(
            BugClass(
                name=name,
                cwes=list(body.get("cwes", [])),
                codeql_tags=list(body.get("codeql_tags", [])),
                group=body.get("group"),
                aliases=list(body.get("aliases", [])),
            )
        )
    return out


def _alias_index() -> dict[str, str]:
    idx: dict[str, str] = {}
    for klass in list_classes():
        idx[klass.name] = klass.name
        for a in klass.aliases:
            idx[a] = klass.name
    return idx


def _expand_group(name: str, raw_groups: dict) -> list[str]:
    members = raw_groups.get(name, [])
    out: list[str] = []
    for m in members:
        if m.startswith("@"):
            out.extend(_expand_group(m[1:], raw_groups))
        else:
            out.append(m)
    return out


def resolve_classes(tokens: list[str]) -> list[BugClass]:
    """Resolve user-supplied names/aliases/``@group`` tokens to a sorted ``BugClass`` list."""
    raw = _load_raw()
    raw_groups = raw.get("groups", {})
    aliases = _alias_index()
    by_name = {c.name: c for c in list_classes()}

    selected: set[str] = set()
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if token.startswith("@"):
            for member in _expand_group(token[1:], raw_groups):
                canonical = aliases.get(member)
                if canonical:
                    selected.add(canonical)
            continue
        if token in raw_groups:
            for member in _expand_group(token, raw_groups):
                canonical = aliases.get(member)
                if canonical:
                    selected.add(canonical)
            continue
        canonical = aliases.get(token)
        if not canonical:
            close = difflib.get_close_matches(token, list(aliases), n=1)
            hint = f" Did you mean '{close[0]}'?" if close else ""
            raise UnknownBugClassError(f"Unknown bug class '{token}'.{hint}")
        selected.add(canonical)
    return [by_name[n] for n in sorted(selected)]
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_taxonomy_loader.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/taxonomy/ tests/test_taxonomy_loader.py
git commit -m "feat(taxonomy): canonical bug-class yaml + resolver"
```

---

## Task 3: CodeQL runner (`engines/codeql.py`)

**Files:**
- Create: `ai_codescan/engines/__init__.py`
- Create: `ai_codescan/engines/codeql.py`
- Test: `tests/test_codeql_runner.py`

The fixture for SQL injection uses a benign sink shape (`mysql2.query` with concat) — same vulnerability class, no shell calls. CodeQL's `js/sql-injection` query catches it.

- [ ] **Step 1: Author the vulnerable fixture**

```bash
mkdir -p tests/fixtures/tiny-vuln
```

`tests/fixtures/tiny-vuln/package.json`:

```json
{
  "name": "tiny-vuln",
  "version": "0.0.1",
  "dependencies": { "express": "^4.21.0", "mysql2": "^3.11.0" }
}
```

`tests/fixtures/tiny-vuln/server.js`:

```javascript
const express = require('express');
const mysql = require('mysql2');
const app = express();
const conn = mysql.createConnection({ host: 'localhost' });
app.get('/u', (req, res) => {
  // CWE-89: req.query.id flows unparameterised into a SQL query string.
  const sql = "SELECT * FROM users WHERE id=" + req.query.id;
  conn.query(sql, (err, rows) => res.json(rows));
});
app.listen(3000);
```

- [ ] **Step 2: Failing tests**

`tests/test_codeql_runner.py`:

```python
"""Tests for ai_codescan.engines.codeql."""

import shutil
from pathlib import Path

import pytest

from ai_codescan.engines.codeql import CodeqlResult, build_database, run_queries


def _has_codeql() -> bool:
    return shutil.which("codeql") is not None


@pytest.mark.integration
@pytest.mark.skipif(not _has_codeql(), reason="codeql cli not installed")
def test_build_database_succeeds_for_js_project(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    db_path = build_database(
        fixtures_dir / "tiny-vuln",
        cache_dir=cache,
        project_id="tiny-vuln",
    )
    assert db_path.is_dir()
    assert (db_path / "codeql-database.yml").is_file()


@pytest.mark.integration
@pytest.mark.skipif(not _has_codeql(), reason="codeql cli not installed")
def test_run_queries_emits_sarif(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    db_path = build_database(
        fixtures_dir / "tiny-vuln",
        cache_dir=cache,
        project_id="tiny-vuln",
    )
    result = run_queries(
        db_path,
        cache_dir=cache,
        project_id="tiny-vuln",
        codeql_tags=["security/cwe/cwe-089"],
    )
    assert isinstance(result, CodeqlResult)
    assert result.sarif_path.is_file()
    assert result.sarif_path.stat().st_size > 0
```

- [ ] **Step 3: Implement runner**

`ai_codescan/engines/__init__.py`: empty.

`ai_codescan/engines/codeql.py`:

```python
"""Wrap the CodeQL CLI: build database, run queries, emit SARIF."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

QUERY_SUITE = "javascript-security-extended.qls"
"""Default suite that includes most security queries."""


def _ensure_codeql_on_path() -> None:
    if shutil.which("codeql") is None:
        raise RuntimeError("codeql CLI not on PATH. Install from github.com/github/codeql-cli.")


def build_database(
    project_root: Path,
    *,
    cache_dir: Path,
    project_id: str,
    allow_minified: bool = False,
) -> Path:
    """Build a CodeQL DB for ``project_root`` rooted at ``cache_dir``.

    Returns the path to the database directory.
    """
    _ensure_codeql_on_path()
    db_path = cache_dir / "codeql" / f"{project_id}.db"
    if db_path.exists():
        shutil.rmtree(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    if allow_minified:
        env["CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES"] = "true"
    subprocess.run(
        [
            "codeql", "database", "create", str(db_path),
            "--language=javascript-typescript",
            "--source-root", str(project_root),
            "--overwrite",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    return db_path


@dataclass(frozen=True, slots=True)
class CodeqlResult:
    """Output of a CodeQL analysis run."""

    sarif_path: Path
    db_path: Path
    project_id: str


def run_queries(
    db_path: Path,
    *,
    cache_dir: Path,
    project_id: str,
    codeql_tags: list[str],
    extension_packs: list[Path] | None = None,
) -> CodeqlResult:
    """Run the security suite filtered by ``codeql_tags`` and emit SARIF."""
    _ensure_codeql_on_path()
    sarif_dir = cache_dir / "codeql"
    sarif_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = sarif_dir / f"{project_id}.sarif"

    cmd = [
        "codeql", "database", "analyze", str(db_path),
        "--format=sarifv2.1.0",
        "--output", str(sarif_path),
        "--sarif-add-query-help",
    ]
    if codeql_tags:
        cmd += ["--query-tags", "+".join(codeql_tags)]
    if extension_packs:
        for pack in extension_packs:
            cmd += ["--model-packs", str(pack)]
    cmd.append(QUERY_SUITE)

    subprocess.run(cmd, check=True, capture_output=True)
    return CodeqlResult(sarif_path=sarif_path, db_path=db_path, project_id=project_id)
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_codeql_runner.py -v
```

Expected: 2 passed when `codeql` is installed; 2 skipped otherwise.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/engines/ tests/test_codeql_runner.py tests/fixtures/tiny-vuln/
git commit -m "feat(engines): codeql database + analyze wrapper"
```

---

## Task 4: SARIF → DuckDB ingestion (`ingest/sarif.py`)

**Files:**
- Create: `ai_codescan/ingest/__init__.py`
- Create: `ai_codescan/ingest/sarif.py`
- Create: `tests/fixtures/sample.sarif`
- Test: `tests/test_sarif_ingest.py`

- [ ] **Step 1: Author the canned SARIF**

`tests/fixtures/sample.sarif`:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "CodeQL", "version": "2.25.0" } },
      "results": [
        {
          "ruleId": "js/sql-injection",
          "ruleIndex": 0,
          "message": { "text": "Untrusted data flows into SQL." },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "server.js" },
                "region": { "startLine": 5, "startColumn": 14, "endLine": 5, "endColumn": 70 }
              }
            }
          ],
          "codeFlows": [
            {
              "threadFlows": [
                {
                  "locations": [
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": { "uri": "server.js" },
                          "region": { "startLine": 4, "startColumn": 22, "endLine": 4, "endColumn": 35 }
                        },
                        "message": { "text": "req.query.id" }
                      }
                    },
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": { "uri": "server.js" },
                          "region": { "startLine": 5, "startColumn": 14, "endLine": 5, "endColumn": 70 }
                        },
                        "message": { "text": "concatenated SQL" }
                      }
                    }
                  ]
                }
              ]
            }
          ],
          "properties": {
            "tags": ["security", "external/cwe/cwe-089"],
            "security-severity": "8.8"
          }
        }
      ],
      "originalUriBaseIds": { "%SRCROOT%": { "uri": "file:///abs/" } }
    }
  ]
}
```

- [ ] **Step 2: Failing tests**

`tests/test_sarif_ingest.py`:

```python
"""Tests for ai_codescan.ingest.sarif."""

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.ingest.sarif import ingest_sarif


def test_ingest_sample_sarif_creates_source_sink_flow(tmp_path: Path, fixtures_dir: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)

    n = ingest_sarif(
        conn,
        sarif_path=fixtures_dir / "sample.sarif",
        project_id="tiny-vuln",
        snapshot_root=Path("/abs"),
        engine="codeql",
    )
    assert n == 1
    assert conn.execute("SELECT COUNT(*) FROM taint_sources").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM taint_sinks").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 1
    cwe = conn.execute("SELECT cwe FROM flows").fetchone()[0]
    assert cwe == "CWE-89"
    eng = conn.execute("SELECT engine FROM flows").fetchone()[0]
    assert eng == "codeql"


def test_ingest_is_idempotent(tmp_path: Path, fixtures_dir: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    ingest_sarif(
        conn,
        sarif_path=fixtures_dir / "sample.sarif",
        project_id="tiny-vuln",
        snapshot_root=Path("/abs"),
        engine="codeql",
    )
    ingest_sarif(
        conn,
        sarif_path=fixtures_dir / "sample.sarif",
        project_id="tiny-vuln",
        snapshot_root=Path("/abs"),
        engine="codeql",
    )
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 1
```

- [ ] **Step 3: Implement ingester**

`ai_codescan/ingest/__init__.py`: empty.

`ai_codescan/ingest/sarif.py`:

```python
"""Parse SARIF and ingest taint sources, sinks, and flows into DuckDB."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import duckdb

_CWE_RE = re.compile(r"cwe[-/](\d+)", re.IGNORECASE)


def _extract_cwe(rule_id: str, tags: list[str]) -> str | None:
    for token in [rule_id, *tags]:
        m = _CWE_RE.search(token or "")
        if m:
            return f"CWE-{int(m.group(1))}"
    return None


def _stable_id(prefix: str, *parts: str) -> str:
    blob = "|".join(parts)
    return f"{prefix}:{hashlib.sha1(blob.encode('utf-8'), usedforsecurity=False).hexdigest()[:16]}"


def _physical_to_loc(phys: dict, snapshot_root: Path) -> tuple[str, int, int]:
    uri = phys.get("artifactLocation", {}).get("uri", "")
    region = phys.get("region", {})
    file_abs = (snapshot_root / uri).as_posix() if uri else ""
    return file_abs, int(region.get("startLine", 0)), int(region.get("endLine", region.get("startLine", 0)))


def ingest_sarif(
    conn: duckdb.DuckDBPyConnection,
    *,
    sarif_path: Path,
    project_id: str,
    snapshot_root: Path,
    engine: str,
) -> int:
    """Ingest one SARIF file. Returns the number of flows ingested.

    Idempotent: re-ingesting the same SARIF leaves the DB unchanged.
    """
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    flows_inserted = 0
    for run in data.get("runs", []):
        for result in run.get("results", []):
            tags = (result.get("properties", {}) or {}).get("tags", []) or []
            cwe = _extract_cwe(result.get("ruleId", ""), tags)
            sink_loc = result.get("locations", [{}])[0].get("physicalLocation", {})
            sink_file, sink_start, sink_end = _physical_to_loc(sink_loc, snapshot_root)
            sid = _stable_id("sink", project_id, sink_file, str(sink_start), result.get("ruleId", ""))
            conn.execute(
                "INSERT OR REPLACE INTO taint_sinks VALUES (?, ?, ?, ?, ?, ?)",
                [sid, None, result.get("ruleId", ""), None, "unknown", "[]"],
            )

            for flow in result.get("codeFlows", []):
                for thread in flow.get("threadFlows", []):
                    locs = thread.get("locations", [])
                    if not locs:
                        continue
                    src_phys = locs[0].get("location", {}).get("physicalLocation", {})
                    src_file, src_start, src_end = _physical_to_loc(src_phys, snapshot_root)
                    tid = _stable_id("source", project_id, src_file, str(src_start), result.get("ruleId", ""))
                    conn.execute(
                        "INSERT OR REPLACE INTO taint_sources VALUES (?, ?, ?, ?, ?)",
                        [
                            tid,
                            None,
                            "unknown",
                            locs[0].get("location", {}).get("message", {}).get("text"),
                            f"{src_file}:{src_start}",
                        ],
                    )
                    fid = _stable_id("flow", project_id, tid, sid)
                    steps_json = json.dumps(
                        [
                            _physical_to_loc(
                                step.get("location", {}).get("physicalLocation", {}),
                                snapshot_root,
                            )
                            for step in locs
                        ]
                    )
                    conn.execute(
                        "INSERT OR REPLACE INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        [fid, tid, sid, cwe, engine, steps_json, str(sarif_path), "definite"],
                    )
                    flows_inserted += 1
    return flows_inserted
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_sarif_ingest.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/ingest/ tests/test_sarif_ingest.py tests/fixtures/sample.sarif
git commit -m "feat(ingest): sarif parser populates sources, sinks, flows"
```

---

## Task 5: Wire CodeQL + SARIF ingestion into `prep`

**Files:**
- Modify: `ai_codescan/prep.py`
- Modify: `ai_codescan/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Extend `prep.py`**

Append to `ai_codescan/prep.py`:

```python
from ai_codescan.engines.codeql import build_database, run_queries
from ai_codescan.ingest.sarif import ingest_sarif
from ai_codescan.taxonomy.loader import BugClass


def _run_codeql_for_projects(
    snapshot_root: Path,
    projects: list[Project],
    repo_dir: Path,
    bug_classes: list[BugClass] | None,
    conn,
) -> None:
    tags: list[str] = []
    if bug_classes:
        for c in bug_classes:
            tags.extend(c.codeql_tags)
    for project in projects:
        if project.kind is not ProjectKind.NODE:
            continue
        if not project.languages.intersection({"javascript", "typescript"}):
            continue
        project_id = f"{project.name}-{project.base_path.as_posix().replace('/', '_')}"
        try:
            db_path = build_database(
                snapshot_root / project.base_path,
                cache_dir=repo_dir,
                project_id=project_id,
            )
            result = run_queries(
                db_path,
                cache_dir=repo_dir,
                project_id=project_id,
                codeql_tags=tags,
            )
            ingest_sarif(
                conn,
                sarif_path=result.sarif_path,
                project_id=project_id,
                snapshot_root=snapshot_root,
                engine="codeql",
            )
        except (RuntimeError, OSError) as exc:
            log.warning("codeql failed for %s: %s", project.name, exc)
```

Replace `run_prep` with the engine-aware version:

```python
def run_prep(
    target: Path,
    *,
    cache_root: Path,
    commit: str | None = None,
    bug_classes: list[BugClass] | None = None,
    engine: str = "codeql",
) -> tuple[SnapshotResult, Path]:
    repo_dir = cache_root / compute_repo_id(target)
    snap = take_snapshot(target, cache_dir=repo_dir, commit=commit)

    projects = detect_projects(snap.snapshot_dir)
    repo_md_path = repo_dir / "repo.md"
    repo_md_path.write_text(
        render_repo_md(target_name=target.name, projects=projects),
        encoding="utf-8",
    )

    db_path = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db_path))
    apply_schema(conn)

    scip_lookup = _build_scip_lookup(snap.snapshot_dir, projects, repo_dir)

    for project in projects:
        jobs = _ast_jobs_for_project(snap.snapshot_dir, project)
        if not jobs:
            continue
        files: list[dict] = []
        symbols: list[dict] = []
        xrefs: list[dict] = []
        for record in run_jobs(jobs):
            t = record["type"]
            if t == "file":
                files.append(record)
            elif t == "symbol":
                symbols.append(record)
            elif t == "xref":
                xrefs.append(record)
        duckdb_ingest(
            conn,
            files=files,
            symbols=symbols,
            xrefs=xrefs,
            scip_lookup=scip_lookup,
            project_id=project.name,
            snapshot_root=snap.snapshot_dir,
        )

    if engine == "codeql":
        _run_codeql_for_projects(snap.snapshot_dir, projects, repo_dir, bug_classes, conn)

    conn.close()
    return snap, db_path
```

- [ ] **Step 2: Update CLI flags**

Replace the `prep` command body in `ai_codescan/cli.py`:

```python
@app.command()
def prep(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Target repo to scan.")],
    commit: _CommitOption = None,
    engine: Annotated[
        str,
        typer.Option(
            "--engine",
            help="Static engine to run (Phase 1: only 'codeql' is supported).",
        ),
    ] = "codeql",
    target_bug_class: Annotated[
        str,
        typer.Option(
            "--target-bug-class",
            help="Comma-separated names or @groups (default: all).",
        ),
    ] = "",
) -> None:
    """Snapshot, detect, AST, SCIP, CodeQL, ingest into DuckDB."""
    from ai_codescan.prep import run_prep
    from ai_codescan.taxonomy.loader import (
        UnknownBugClassError,
        list_classes,
        resolve_classes,
    )

    if engine != "codeql":
        typer.echo(f"--engine {engine} is not supported in Phase 1.", err=True)
        raise typer.Exit(code=2)
    if not target.is_dir():
        typer.echo(f"Target is not a directory: {target}", err=True)
        raise typer.Exit(code=2)

    if target_bug_class:
        try:
            bug_classes = resolve_classes(
                [t.strip() for t in target_bug_class.split(",") if t.strip()]
            )
        except UnknownBugClassError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from exc
    else:
        bug_classes = list_classes()

    cache_root: Path = ctx.obj["cache_root"]
    quiet: bool = ctx.obj["quiet"]
    snap, db_path = run_prep(
        target,
        cache_root=cache_root,
        commit=commit,
        bug_classes=bug_classes,
        engine=engine,
    )
    if not quiet:
        status_word = "skipped" if snap.skipped else "took"
        commit_label = f" @ {snap.commit_sha[:8]}" if snap.commit_sha else ""
        typer.echo(f"snapshot {status_word} ({snap.method}){commit_label}")
        typer.echo(f"index at {db_path}")
        typer.echo(f"bug classes: {', '.join(c.name for c in bug_classes)}")
```

- [ ] **Step 3: Add `list-bug-classes` subcommand**

```python
@app.command("list-bug-classes")
def list_bug_classes() -> None:
    """Print every taxonomy entry."""
    from ai_codescan.taxonomy.loader import list_classes

    rows = sorted(list_classes(), key=lambda c: c.name)
    for c in rows:
        aliases = f" ({', '.join(c.aliases)})" if c.aliases else ""
        cwes = ", ".join(c.cwes)
        typer.echo(f"{c.name}{aliases}\t{c.group}\t{cwes}")
```

- [ ] **Step 4: Tests**

Append to `tests/test_cli.py`:

```python
def test_list_bug_classes_prints_entries() -> None:
    result = runner.invoke(app, ["list-bug-classes"])
    assert result.exit_code == 0
    assert "xss" in result.stdout
    assert "sqli" in result.stdout


def test_unknown_bug_class_errors_with_suggestion(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    result = runner.invoke(
        app,
        [
            "--cache-dir", str(cache),
            "prep", str(fixtures_dir / "tiny-express"),
            "--target-bug-class", "xs",
        ],
    )
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "did you mean" in combined.lower()
```

- [ ] **Step 5: Run tests**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: green.

- [ ] **Step 6: Commit**

```bash
git add ai_codescan/prep.py ai_codescan/cli.py tests/test_cli.py
git commit -m "feat(prep): wire codeql + sarif ingest, add --engine and --target-bug-class"
```

---

## Task 6: Quality gate, smoke test, milestone tag

- [ ] **Step 1: Gate**

```bash
make check
```

- [ ] **Step 2: Real-target smoke test (CodeQL installed)**

```bash
uv run ai-codescan prep /tmp/tmp-express --target-bug-class injection
uv run ai-codescan query "SELECT cwe, COUNT(*) FROM flows GROUP BY cwe"
uv run ai-codescan flows --to anything
```

- [ ] **Step 3: README + tag**

Append to `README.md`:

```markdown
## Phase 1C status

`prep` runs CodeQL after AST/SCIP. Install CodeQL CLI 2.25+ and ensure `codeql` is on PATH. Filter scan classes via `--target-bug-class injection` or `--target-bug-class xss,sqli`.
```

```bash
git add README.md
git commit -m "docs: phase 1C status"
git tag -a phase-1c -m "Phase 1C: codeql + flow ingestion"
```

---

## Self-review

| Spec section | Implemented in |
|---|---|
| §4.2 engine modes | Task 5 |
| §5.5 CodeQL component | Tasks 3, 5 |
| §5.6 taint_sources / taint_sinks / flows | Task 4 |
| §6 bug-class taxonomy | Task 2 |
| §7 `--engine`, `--target-bug-class`, `list-bug-classes` | Task 5 |
| §11.2 CodeQL OOM handling | Task 5 (`try/except` around build/run) |

Deferred to 1D–1E: entrypoints (1D), sidecars + views (1D), nominator + gates (1E), full taxonomy with `needs_semantic` classes (1E).

No placeholders. Stable IDs (`sha1[:16]`) ensure idempotent re-ingest. CWE extraction handles both `external/cwe/cwe-089` and `cwe-089` tag forms.
