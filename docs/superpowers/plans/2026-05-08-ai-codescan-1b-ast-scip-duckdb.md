# AI_Codescan 1B — AST + SCIP + DuckDB Symbols Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `ai-codescan prep` to extract ASTs (ts-morph + parse5 + tree-sitter), build a SCIP index, and populate DuckDB with `files`, `symbols`, and `xrefs`. After this plan, `ai-codescan query` and `ai-codescan flows --from/--to` work even though no taint engine has run yet.

**Architecture:** Heavy lifting moves to a pinned-version Node worker invoked via subprocess from Python. Worker reads project descriptors from stdin (JSON), writes AST/symbol records as JSON Lines to stdout. SCIP indexer is shell-invoked. Both feed into DuckDB via a single ingestion pass.

**Tech Stack:** Python additions: `duckdb>=1.1`, `protobuf>=5.28`, `xxhash>=3.5` (for fallback content-hash IDs). Node side: pinned `typescript@5.7.3`, `ts-morph@26.0.0`, `parse5@7.2.1`, `tree-sitter@0.22`, `tree-sitter-typescript@0.23`, `@sourcegraph/scip-typescript` invoked as a separate CLI.

**Reference spec:** §5.3, §5.4, §5.6 (subset: `files`, `symbols`, `xrefs`, materialized views).

**Depends on:** Plan 1A complete (snapshot + stack-detect produce `repo.md`).

---

## File Structure (added)

```
AI_Analysis/
├── ai_codescan/
│   ├── ast/
│   │   ├── __init__.py
│   │   ├── worker_proto.py        # Python ↔ Node JSON protocol types
│   │   ├── runner.py              # Python wrapper that spawns the Node worker
│   │   └── node_worker/
│   │       ├── package.json
│   │       ├── pnpm-lock.yaml     # generated, committed
│   │       ├── worker.mjs         # entry: dispatches to ts/html extractors
│   │       ├── extract_ts.mjs     # ts-morph extractor
│   │       ├── extract_html.mjs   # parse5 extractor
│   │       └── extract_treesitter.mjs  # tree-sitter fallback
│   ├── index/
│   │   ├── __init__.py
│   │   ├── duckdb_schema.py       # DDL strings + apply()
│   │   ├── duckdb_ingest.py       # files/symbols/xrefs ingestion
│   │   └── scip.py                # scip-typescript wrapper + protobuf parse
│   └── third_party/
│       └── scip_pb2.py            # vendored protobuf-generated module
└── tests/
    ├── test_ast_runner.py
    ├── test_index_scip.py
    ├── test_index_duckdb.py
    ├── test_cli_query.py
    └── fixtures/
        └── tiny-flow/             # used in 1B and later
            ├── package.json
            ├── tsconfig.json
            └── src/{handler.ts,db.ts}
```

---

## Task 1: Add new dependencies

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add deps**

In `pyproject.toml`, extend the `dependencies` list:

```toml
[project]
dependencies = [
  "typer>=0.15.1",
  "duckdb>=1.1.3",
  "protobuf>=5.28",
  "xxhash>=3.5",
]

[dependency-groups]
dev = [
  "pytest>=8.3",
  "pytest-cov>=5.0",
  "ruff>=0.7",
  "ty>=0.0.1a1",
  "grpcio-tools>=1.66",   # protoc, used to regenerate scip_pb2.py
]
```

- [ ] **Step 2: Install**

```bash
cd /home/robin/Hacking/AI_Analysis
uv sync --all-groups
uv run python -c "import duckdb, google.protobuf, xxhash; print('ok')"
```

Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "chore(deps): add duckdb, protobuf, xxhash"
```

---

## Task 2: Vendor the SCIP protobuf module

**Files:**
- Create: `ai_codescan/third_party/__init__.py`
- Create: `ai_codescan/third_party/scip_pb2.py` (generated, committed)
- Create: `scripts/regen_scip_proto.sh`

- [ ] **Step 1: Add the regeneration script**

`scripts/regen_scip_proto.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
PROTO_URL="https://raw.githubusercontent.com/sourcegraph/scip/v0.7.1/scip.proto"
OUT_DIR="ai_codescan/third_party"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
curl -fsSL "$PROTO_URL" -o "$TMPDIR/scip.proto"
uv run python -m grpc_tools.protoc \
  --proto_path="$TMPDIR" \
  --python_out="$OUT_DIR" \
  "$TMPDIR/scip.proto"
echo "regenerated $OUT_DIR/scip_pb2.py"
```

- [ ] **Step 2: Run the regeneration**

```bash
mkdir -p ai_codescan/third_party
touch ai_codescan/third_party/__init__.py
chmod +x scripts/regen_scip_proto.sh
bash scripts/regen_scip_proto.sh
ls ai_codescan/third_party/
```

Expected: `__init__.py  scip_pb2.py`.

- [ ] **Step 3: Smoke test the import**

```bash
uv run python -c "from ai_codescan.third_party import scip_pb2; print(scip_pb2.Index.DESCRIPTOR.name)"
```

Expected: `Index`.

- [ ] **Step 4: Commit**

```bash
git add scripts/regen_scip_proto.sh ai_codescan/third_party/
git commit -m "chore: vendor SCIP protobuf module + regen script"
```

---

## Task 3: Node worker bootstrap

**Files:**
- Create: `ai_codescan/ast/__init__.py`
- Create: `ai_codescan/ast/node_worker/package.json`
- Create: `ai_codescan/ast/node_worker/worker.mjs`

- [ ] **Step 1: Author `package.json` with pinned versions**

`ai_codescan/ast/node_worker/package.json`:

```json
{
  "name": "ai-codescan-ast-worker",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "engines": { "node": ">=22.0.0" },
  "dependencies": {
    "ts-morph": "26.0.0",
    "typescript": "5.7.3",
    "parse5": "7.2.1",
    "tree-sitter": "0.22.4",
    "tree-sitter-typescript": "0.23.2"
  },
  "scripts": {
    "worker": "node worker.mjs"
  }
}
```

- [ ] **Step 2: Generate the lockfile**

```bash
cd ai_codescan/ast/node_worker
pnpm install --lockfile-only
```

(Falls back to `npm install --package-lock-only` if pnpm is unavailable; the file is committed regardless.)

- [ ] **Step 3: Author `worker.mjs` (dispatch shell only)**

`ai_codescan/ast/node_worker/worker.mjs`:

```javascript
#!/usr/bin/env node
// Worker reads one JSON job per stdin line, writes JSONL records to stdout.
// Job: { kind: "ts" | "html" | "treesitter", projectRoot, files: [...], tsconfig?: string }
// Output records: { type, file, ... }; one terminator { type: "done", jobId } per job.

import { createInterface } from "node:readline";

async function dispatch(job) {
  switch (job.kind) {
    case "ts": {
      const m = await import("./extract_ts.mjs");
      return m.run(job);
    }
    case "html": {
      const m = await import("./extract_html.mjs");
      return m.run(job);
    }
    case "treesitter": {
      const m = await import("./extract_treesitter.mjs");
      return m.run(job);
    }
    default:
      throw new Error(`unknown kind: ${job.kind}`);
  }
}

const rl = createInterface({ input: process.stdin });
for await (const line of rl) {
  if (!line.trim()) continue;
  let job;
  try {
    job = JSON.parse(line);
  } catch (e) {
    process.stdout.write(JSON.stringify({ type: "error", message: String(e) }) + "\n");
    continue;
  }
  try {
    for await (const record of dispatch(job)) {
      process.stdout.write(JSON.stringify(record) + "\n");
    }
    process.stdout.write(JSON.stringify({ type: "done", jobId: job.jobId ?? null }) + "\n");
  } catch (e) {
    process.stdout.write(
      JSON.stringify({ type: "error", jobId: job.jobId ?? null, message: String(e) }) + "\n",
    );
  }
}
```

- [ ] **Step 4: Stub the three extractor modules**

`ai_codescan/ast/node_worker/extract_ts.mjs`:

```javascript
export async function* run(job) {
  yield { type: "stub", kind: "ts", filesRequested: job.files.length };
}
```

`ai_codescan/ast/node_worker/extract_html.mjs`:

```javascript
export async function* run(job) {
  yield { type: "stub", kind: "html", filesRequested: job.files.length };
}
```

`ai_codescan/ast/node_worker/extract_treesitter.mjs`:

```javascript
export async function* run(job) {
  yield { type: "stub", kind: "treesitter", filesRequested: job.files.length };
}
```

- [ ] **Step 5: Smoke-test the worker manually**

```bash
cd /home/robin/Hacking/AI_Analysis/ai_codescan/ast/node_worker
echo '{"kind":"ts","projectRoot":".","files":["a.ts","b.ts"]}' | node worker.mjs
```

Expected: two JSONL lines, the second of which is `{"type":"done","jobId":null}`.

- [ ] **Step 6: Commit**

```bash
git add ai_codescan/ast/__init__.py ai_codescan/ast/node_worker/
git commit -m "feat(ast): node worker scaffold with extractor dispatch"
```

---

## Task 4: ts-morph extractor — symbols and xrefs

**Files:**
- Modify: `ai_codescan/ast/node_worker/extract_ts.mjs`

The extractor walks each `.ts` / `.tsx` / `.js` / `.jsx` file in the project and emits records. Two record kinds for 1B: `symbol` (function / class / method / variable) and `xref` (call / import / reference).

- [ ] **Step 1: Implement the extractor**

Replace `extract_ts.mjs` with:

```javascript
import { Project, SyntaxKind } from "ts-morph";
import { createHash } from "node:crypto";

function syntheticId(file, kind, name, line) {
  const hash = createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex");
  return `synthetic:${hash.slice(0, 12)}`;
}

function recordSymbol(node, kind, displayName) {
  const sf = node.getSourceFile();
  const start = node.getStartLineNumber();
  const end = node.getEndLineNumber();
  const file = sf.getFilePath();
  return {
    type: "symbol",
    file,
    kind,
    name: displayName,
    range: [start, end],
    syntheticId: syntheticId(file, kind, displayName, start),
  };
}

export async function* run(job) {
  const tsconfigPath = job.tsconfig ?? null;
  const project = tsconfigPath
    ? new Project({ tsConfigFilePath: tsconfigPath, skipAddingFilesFromTsConfig: false })
    : new Project({ compilerOptions: { allowJs: true, target: 99 } });

  if (!tsconfigPath) {
    project.addSourceFilesAtPaths(job.files);
  }

  for (const sf of project.getSourceFiles()) {
    const file = sf.getFilePath();
    yield {
      type: "file",
      file,
      lang: sf.getExtension().slice(1),
      lineCount: sf.getEndLineNumber(),
    };

    for (const fn of sf.getFunctions()) {
      yield recordSymbol(fn, "function", fn.getName() ?? "<anonymous>");
    }
    for (const cls of sf.getClasses()) {
      yield recordSymbol(cls, "class", cls.getName() ?? "<anonymous>");
      for (const m of cls.getMethods()) {
        yield recordSymbol(m, "method", `${cls.getName() ?? "<anonymous>"}.${m.getName()}`);
      }
    }
    for (const v of sf.getVariableDeclarations()) {
      yield recordSymbol(v, "variable", v.getName());
    }

    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const expr = call.getExpression();
      yield {
        type: "xref",
        kind: "call",
        file,
        line: call.getStartLineNumber(),
        callerSyntheticId: null, // populated by Python ingester via range lookup
        calleeText: expr.getText(),
      };
    }

    for (const imp of sf.getImportDeclarations()) {
      yield {
        type: "xref",
        kind: "import",
        file,
        line: imp.getStartLineNumber(),
        moduleSpecifier: imp.getModuleSpecifierValue(),
      };
    }
  }
}
```

- [ ] **Step 2: Manual smoke test**

```bash
cd /home/robin/Hacking/AI_Analysis/ai_codescan/ast/node_worker
mkdir -p /tmp/smoke && cat > /tmp/smoke/x.ts <<'EOF'
export function greet(name: string) { console.log(name); }
greet("hi");
EOF
echo '{"kind":"ts","projectRoot":"/tmp/smoke","files":["/tmp/smoke/x.ts"]}' | node worker.mjs
```

Expected: at least one `symbol` record for `greet`, one `xref:call` record, then `done`.

- [ ] **Step 3: Commit**

```bash
git add ai_codescan/ast/node_worker/extract_ts.mjs
git commit -m "feat(ast): ts-morph extractor for symbols and xrefs"
```

---

## Task 5: parse5 HTML extractor

**Files:**
- Modify: `ai_codescan/ast/node_worker/extract_html.mjs`

- [ ] **Step 1: Implement HTML extraction**

Replace `extract_html.mjs` with:

```javascript
import { parse } from "parse5";
import { readFileSync } from "node:fs";

function* walk(node, file, lineMap, ancestors) {
  if (!node) return;
  if (node.tagName === "script") {
    const start = node.sourceCodeLocation?.startLine ?? 0;
    const end = node.sourceCodeLocation?.endLine ?? start;
    const inline = node.childNodes?.[0]?.value ?? null;
    const srcAttr = node.attrs?.find((a) => a.name === "src")?.value ?? null;
    yield {
      type: "html_script",
      file,
      range: [start, end],
      src: srcAttr,
      inline,
    };
  }
  if (node.attrs) {
    for (const attr of node.attrs) {
      if (attr.name.startsWith("on")) {
        const loc = node.sourceCodeLocation?.attrs?.[attr.name];
        yield {
          type: "html_handler",
          file,
          tag: node.tagName,
          attr: attr.name,
          line: loc?.startLine ?? 0,
          js: attr.value,
        };
      }
    }
  }
  for (const child of node.childNodes ?? []) {
    yield* walk(child, file, lineMap, ancestors);
  }
}

export async function* run(job) {
  for (const file of job.files) {
    const html = readFileSync(file, "utf8");
    const doc = parse(html, { sourceCodeLocationInfo: true });
    yield { type: "file", file, lang: "html", lineCount: html.split("\n").length };
    yield* walk(doc, file, null, []);
  }
}
```

- [ ] **Step 2: Manual smoke test**

```bash
cat > /tmp/smoke/page.html <<'EOF'
<!doctype html>
<html><body>
  <button onclick="alert(1)">x</button>
  <script src="/app.js"></script>
  <script>console.log("hi")</script>
</body></html>
EOF
echo '{"kind":"html","projectRoot":"/tmp/smoke","files":["/tmp/smoke/page.html"]}' | node worker.mjs
```

Expected: one `html_handler` (`onclick`), two `html_script` records, then `done`.

- [ ] **Step 3: Commit**

```bash
git add ai_codescan/ast/node_worker/extract_html.mjs
git commit -m "feat(ast): parse5 html extractor for inline scripts and handlers"
```

---

## Task 6: tree-sitter fallback extractor

**Files:**
- Modify: `ai_codescan/ast/node_worker/extract_treesitter.mjs`

Used when files are outside any tsconfig or the file has parse errors that ts-morph rejects.

- [ ] **Step 1: Implement**

Replace `extract_treesitter.mjs` with:

```javascript
import Parser from "tree-sitter";
import TS from "tree-sitter-typescript";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const parser = new Parser();
parser.setLanguage(TS.typescript);

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

function* descend(node, file) {
  switch (node.type) {
    case "function_declaration":
    case "function":
    case "method_definition": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type === "method_definition" ? "method" : "function",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, "function", name, node.startPosition.row + 1),
      };
      break;
    }
    case "class_declaration": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: "class",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, "class", name, node.startPosition.row + 1),
      };
      break;
    }
    case "call_expression":
      yield {
        type: "xref",
        kind: "call",
        file,
        line: node.startPosition.row + 1,
        callerSyntheticId: null,
        calleeText: node.text,
      };
      break;
    default:
      break;
  }
  for (const child of node.namedChildren) yield* descend(child, file);
}

export async function* run(job) {
  for (const file of job.files) {
    const src = readFileSync(file, "utf8");
    const tree = parser.parse(src);
    yield { type: "file", file, lang: "tsx", lineCount: src.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
```

- [ ] **Step 2: Smoke test**

```bash
cat > /tmp/smoke/loose.ts <<'EOF'
export function broken(x { return x; }
EOF
echo '{"kind":"treesitter","projectRoot":"/tmp/smoke","files":["/tmp/smoke/loose.ts"]}' | node worker.mjs
```

Expected: one `file` record, possibly one `symbol`, then `done` — tree-sitter is error-tolerant so it parses what it can.

- [ ] **Step 3: Commit**

```bash
git add ai_codescan/ast/node_worker/extract_treesitter.mjs
git commit -m "feat(ast): tree-sitter fallback extractor"
```

---

## Task 7: Python wrapper for the AST worker (`runner.py`)

**Files:**
- Create: `ai_codescan/ast/runner.py`
- Test: `tests/test_ast_runner.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_ast_runner.py`:

```python
"""Tests for ai_codescan.ast.runner."""

from pathlib import Path

import pytest

from ai_codescan.ast.runner import AstJob, run_jobs


def _ensure_worker_installed() -> None:
    worker_dir = Path(__file__).resolve().parents[1] / "ai_codescan/ast/node_worker"
    if not (worker_dir / "node_modules").exists():
        import subprocess

        subprocess.run(["pnpm", "install", "--prefer-offline"], cwd=worker_dir, check=True)


@pytest.mark.integration
def test_run_jobs_yields_records_for_typescript(tmp_path: Path) -> None:
    _ensure_worker_installed()
    src = tmp_path / "x.ts"
    src.write_text("export function greet(n: string) { console.log(n); }\ngreet('hi');\n")
    jobs = [AstJob(kind="ts", project_root=tmp_path, files=[src])]
    records = list(run_jobs(jobs))
    kinds = [r["type"] for r in records]
    assert "file" in kinds
    assert any(r["type"] == "symbol" and r["name"] == "greet" for r in records)
    assert any(r["type"] == "xref" and r["kind"] == "call" for r in records)


@pytest.mark.integration
def test_run_jobs_handles_html(tmp_path: Path) -> None:
    _ensure_worker_installed()
    page = tmp_path / "p.html"
    page.write_text(
        "<!doctype html><body><button onclick='x()'>b</button>"
        "<script>console.log(1)</script></body>"
    )
    jobs = [AstJob(kind="html", project_root=tmp_path, files=[page])]
    records = list(run_jobs(jobs))
    assert any(r["type"] == "html_handler" for r in records)
    assert any(r["type"] == "html_script" for r in records)
```

- [ ] **Step 2: Run tests**

```bash
uv run pytest tests/test_ast_runner.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `runner.py`**

`ai_codescan/ast/runner.py`:

```python
"""Spawn the Node AST worker and stream its JSONL output."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

WORKER_DIR = Path(__file__).resolve().parent / "node_worker"


@dataclass(frozen=True, slots=True)
class AstJob:
    """One worker job."""

    kind: Literal["ts", "html", "treesitter"]
    project_root: Path
    files: list[Path] = field(default_factory=list)
    tsconfig: Path | None = None


def _job_to_dict(job: AstJob, job_id: int) -> dict[str, Any]:
    return {
        "jobId": job_id,
        "kind": job.kind,
        "projectRoot": str(job.project_root),
        "files": [str(f) for f in job.files],
        "tsconfig": str(job.tsconfig) if job.tsconfig else None,
    }


def run_jobs(jobs: Iterable[AstJob]) -> Iterator[dict[str, Any]]:
    """Run each job through the Node worker and yield raw record dicts.

    The worker emits one ``done`` record per job; this function consumes
    those without yielding them so consumers see only data records.
    """
    proc = subprocess.Popen(
        ["node", str(WORKER_DIR / "worker.mjs")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert proc.stdin is not None and proc.stdout is not None

    job_list = list(jobs)
    for idx, job in enumerate(job_list):
        proc.stdin.write(json.dumps(_job_to_dict(job, idx)) + "\n")
    proc.stdin.flush()
    proc.stdin.close()

    expected_done = len(job_list)
    seen_done = 0
    for line in proc.stdout:
        record: dict[str, Any] = json.loads(line)
        if record.get("type") == "done":
            seen_done += 1
            if seen_done >= expected_done:
                break
            continue
        if record.get("type") == "error":
            proc.wait(timeout=5)
            raise RuntimeError(f"AST worker error: {record.get('message')}")
        yield record

    rc = proc.wait(timeout=10)
    stderr = proc.stderr.read() if proc.stderr else ""
    if rc != 0:
        raise RuntimeError(f"AST worker exited {rc}: {stderr}")
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_ast_runner.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/ast/runner.py tests/test_ast_runner.py
git commit -m "feat(ast): python wrapper streaming worker output"
```

---

## Task 8: DuckDB schema (`duckdb_schema.py`)

**Files:**
- Create: `ai_codescan/index/__init__.py`
- Create: `ai_codescan/index/duckdb_schema.py`
- Test: `tests/test_index_duckdb.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_index_duckdb.py`:

```python
"""Tests for ai_codescan.index.duckdb_schema and ingestion."""

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema


def test_apply_schema_creates_phase1_tables(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    tables = {row[0] for row in conn.execute("SHOW TABLES").fetchall()}
    assert {
        "files",
        "symbols",
        "xrefs",
        "taint_sources",
        "taint_sinks",
        "flows",
        "notes",
        "entrypoints",
    } <= tables


def test_apply_schema_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    apply_schema(conn)  # second call must not raise
    assert conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0


def test_views_for_source_sink_navigation(tmp_path: Path) -> None:
    db = tmp_path / "z.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    views = {
        row[0]
        for row in conn.execute(
            "SELECT view_name FROM duckdb_views() WHERE schema_name='main'"
        ).fetchall()
    }
    assert {"v_sources_to_sinks", "v_sinks_from_sources"} <= views
```

- [ ] **Step 2: Run tests**

```bash
uv run pytest tests/test_index_duckdb.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement schema**

`ai_codescan/index/__init__.py`:

```python
```

`ai_codescan/index/duckdb_schema.py`:

```python
"""DuckDB schema for the ai-codescan project DB."""

from __future__ import annotations

import duckdb

PHASE1_TABLES_DDL = """
CREATE TABLE IF NOT EXISTS files (
  path VARCHAR PRIMARY KEY,
  sha256 VARCHAR NOT NULL,
  lang VARCHAR,
  project_id VARCHAR,
  size BIGINT
);

CREATE TABLE IF NOT EXISTS symbols (
  id VARCHAR PRIMARY KEY,
  sym VARCHAR NOT NULL,
  kind VARCHAR NOT NULL,
  file VARCHAR NOT NULL,
  range_start INTEGER NOT NULL,
  range_end INTEGER NOT NULL,
  type VARCHAR,
  display_name VARCHAR
);

CREATE TABLE IF NOT EXISTS xrefs (
  caller_id VARCHAR,
  callee_id VARCHAR,
  kind VARCHAR NOT NULL,
  file VARCHAR,
  line INTEGER
);

CREATE TABLE IF NOT EXISTS taint_sources (
  tid VARCHAR PRIMARY KEY,
  symbol_id VARCHAR,
  class VARCHAR,
  key VARCHAR,
  evidence_loc VARCHAR
);

CREATE TABLE IF NOT EXISTS taint_sinks (
  sid VARCHAR PRIMARY KEY,
  symbol_id VARCHAR,
  class VARCHAR,
  lib VARCHAR,
  parameterization VARCHAR,
  tainted_slots_json VARCHAR
);

CREATE TABLE IF NOT EXISTS flows (
  fid VARCHAR PRIMARY KEY,
  tid VARCHAR,
  sid VARCHAR,
  cwe VARCHAR,
  engine VARCHAR,
  steps_json VARCHAR,
  sarif_ref VARCHAR,
  confidence VARCHAR
);

CREATE TABLE IF NOT EXISTS notes (
  symbol_id VARCHAR,
  layer VARCHAR,
  author VARCHAR,
  content VARCHAR,
  pinned BOOLEAN DEFAULT FALSE,
  ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS entrypoints (
  symbol_id VARCHAR,
  kind VARCHAR,
  signature VARCHAR
);
"""

PHASE2_RESERVED_DDL = """
CREATE TABLE IF NOT EXISTS storage_locations (
  storage_id VARCHAR PRIMARY KEY,
  kind VARCHAR,
  schema_evidence VARCHAR
);

CREATE TABLE IF NOT EXISTS storage_writes (
  storage_id VARCHAR,
  flow_id VARCHAR,
  source_tid VARCHAR,
  symbol_id VARCHAR,
  call_shape_json VARCHAR
);

CREATE TABLE IF NOT EXISTS storage_reads (
  storage_id VARCHAR,
  symbol_id VARCHAR,
  result_binding_id VARCHAR
);

CREATE TABLE IF NOT EXISTS storage_taint (
  storage_id VARCHAR,
  derived_tid VARCHAR,
  contributing_tids_json VARCHAR,
  confidence VARCHAR
);
"""

VIEWS_DDL = """
CREATE OR REPLACE VIEW v_sources_to_sinks AS
SELECT
  ts.symbol_id AS source_symbol_id,
  ts2.symbol_id AS sink_symbol_id,
  list(f.fid)   AS fids,
  list(f.cwe)   AS cwes
FROM flows f
JOIN taint_sources ts  ON ts.tid = f.tid
JOIN taint_sinks   ts2 ON ts2.sid = f.sid
GROUP BY ts.symbol_id, ts2.symbol_id;

CREATE OR REPLACE VIEW v_sinks_from_sources AS
SELECT
  ts2.symbol_id AS sink_symbol_id,
  ts.symbol_id  AS source_symbol_id,
  list(f.fid)   AS fids,
  list(f.cwe)   AS cwes
FROM flows f
JOIN taint_sources ts  ON ts.tid = f.tid
JOIN taint_sinks   ts2 ON ts2.sid = f.sid
GROUP BY ts2.symbol_id, ts.symbol_id;
"""


def apply_schema(conn: duckdb.DuckDBPyConnection) -> None:
    """Apply Phase 1 + Phase 2-reserved tables and the navigation views."""
    conn.execute(PHASE1_TABLES_DDL)
    conn.execute(PHASE2_RESERVED_DDL)
    conn.execute(VIEWS_DDL)
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_index_duckdb.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/index/__init__.py ai_codescan/index/duckdb_schema.py tests/test_index_duckdb.py
git commit -m "feat(index): duckdb schema + navigation views"
```

---

## Task 9: SCIP indexer wrapper (`scip.py`)

**Files:**
- Create: `ai_codescan/index/scip.py`
- Test: `tests/test_index_scip.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_index_scip.py`:

```python
"""Tests for ai_codescan.index.scip."""

import shutil
from pathlib import Path

import pytest

from ai_codescan.index.scip import IndexResult, build_scip_index


def _has_scip_typescript() -> bool:
    return shutil.which("scip-typescript") is not None


@pytest.mark.integration
@pytest.mark.skipif(not _has_scip_typescript(), reason="scip-typescript not installed")
def test_build_scip_index_writes_protobuf(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    (project / "package.json").write_text('{"name":"p"}')
    (project / "tsconfig.json").write_text('{"compilerOptions":{"target":"ES2022"}}')
    (project / "x.ts").write_text("export function f(): number { return 1; }\n")

    cache = tmp_path / "cache"
    cache.mkdir()

    result = build_scip_index(project, cache_dir=cache, project_id="p")

    assert isinstance(result, IndexResult)
    assert result.scip_path.is_file()
    assert result.scip_path.stat().st_size > 0
    documents = list(result.iter_documents())
    assert any(doc.relative_path.endswith("x.ts") for doc in documents)
```

- [ ] **Step 2: Run tests**

```bash
uv run pytest tests/test_index_scip.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement**

`ai_codescan/index/scip.py`:

```python
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

    def iter_documents(self) -> Iterator["scip_pb2.Document"]:
        """Yield each ``scip_pb2.Document`` from the index."""
        index = scip_pb2.Index()
        index.ParseFromString(self.scip_path.read_bytes())
        yield from index.documents


def build_scip_index(project_root: Path, *, cache_dir: Path, project_id: str) -> IndexResult:
    """Run ``scip-typescript`` against ``project_root`` and persist the .scip blob."""
    if shutil.which("scip-typescript") is None:
        raise RuntimeError("scip-typescript is not on PATH; install via npm i -g @sourcegraph/scip-typescript")

    out_dir = cache_dir / "scip"
    out_dir.mkdir(parents=True, exist_ok=True)
    scip_path = out_dir / f"{project_id}.scip"

    subprocess.run(
        [
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
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_index_scip.py -v
```

Expected: passes if `scip-typescript` is installed; otherwise skipped. (Install via `npm i -g @sourcegraph/scip-typescript` — note this in the README.)

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/index/scip.py tests/test_index_scip.py
git commit -m "feat(index): scip-typescript wrapper with document iteration"
```

---

## Task 10: DuckDB ingestion of files / symbols / xrefs

**Files:**
- Create: `ai_codescan/index/duckdb_ingest.py`
- Test: extend `tests/test_index_duckdb.py`

Source of truth for IDs:
1. Try SCIP symbol from the SCIP index lookup-by-(file, range).
2. If not present, fall back to the worker-emitted `syntheticId`.
3. If neither, drop the record and log.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_index_duckdb.py`:

```python
def test_ingest_files_and_symbols(tmp_path: Path) -> None:
    from ai_codescan.index.duckdb_ingest import ingest

    db = tmp_path / "ing.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)

    file_records = [{"file": "/abs/x.ts", "lang": "ts", "lineCount": 10}]
    symbol_records = [
        {
            "type": "symbol",
            "file": "/abs/x.ts",
            "kind": "function",
            "name": "greet",
            "range": [1, 3],
            "syntheticId": "synthetic:abc123",
        }
    ]
    xref_records = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/x.ts",
            "line": 5,
            "callerSyntheticId": None,
            "calleeText": "greet",
        }
    ]
    ingest(
        conn,
        files=file_records,
        symbols=symbol_records,
        xrefs=xref_records,
        scip_lookup={},
        project_id="p",
        snapshot_root=Path("/abs"),
    )
    rows = conn.execute("SELECT id, kind, display_name FROM symbols").fetchall()
    assert ("synthetic:abc123", "function", "greet") in rows
    xref_rows = conn.execute("SELECT kind, file, line FROM xrefs").fetchall()
    assert ("call", "/abs/x.ts", 5) in xref_rows


def test_ingest_prefers_scip_symbol_over_synthetic(tmp_path: Path) -> None:
    from ai_codescan.index.duckdb_ingest import ingest

    db = tmp_path / "ing2.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)

    file_records = [{"file": "/abs/x.ts", "lang": "ts", "lineCount": 10}]
    symbol_records = [
        {
            "type": "symbol",
            "file": "/abs/x.ts",
            "kind": "function",
            "name": "greet",
            "range": [1, 3],
            "syntheticId": "synthetic:abc123",
        }
    ]
    scip_lookup = {("/abs/x.ts", 1, 3): "scip:npm/@p/0.0.1/x.ts/greet#"}
    ingest(
        conn,
        files=file_records,
        symbols=symbol_records,
        xrefs=[],
        scip_lookup=scip_lookup,
        project_id="p",
        snapshot_root=Path("/abs"),
    )
    rows = conn.execute("SELECT id, sym FROM symbols").fetchall()
    assert ("scip:npm/@p/0.0.1/x.ts/greet#", "scip:npm/@p/0.0.1/x.ts/greet#") in rows
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_index_duckdb.py -v
```

Expected: 2 new failures.

- [ ] **Step 3: Implement ingest**

`ai_codescan/index/duckdb_ingest.py`:

```python
"""Ingest AST records (and optional SCIP lookup) into DuckDB."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import duckdb

ScipLookup = dict[tuple[str, int, int], str]
"""Map of (file, range_start, range_end) → SCIP symbol id."""


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    if not path.is_file():
        return ""
    with path.open("rb") as f:
        while chunk := f.read(65_536):
            h.update(chunk)
    return h.hexdigest()


def _resolve_symbol_id(record: dict[str, Any], scip_lookup: ScipLookup) -> str | None:
    file = record["file"]
    rng = record.get("range")
    if rng:
        scip = scip_lookup.get((file, rng[0], rng[1]))
        if scip:
            return scip
    return record.get("syntheticId")


def ingest(
    conn: duckdb.DuckDBPyConnection,
    *,
    files: Iterable[dict[str, Any]],
    symbols: Iterable[dict[str, Any]],
    xrefs: Iterable[dict[str, Any]],
    scip_lookup: ScipLookup,
    project_id: str,
    snapshot_root: Path,
) -> None:
    """Bulk-ingest AST + SCIP records into DuckDB tables."""
    file_rows = []
    for f in files:
        path = Path(f["file"])
        rel = path.as_posix()
        sha = _file_sha256(path) if path.is_absolute() and path.exists() else ""
        size = path.stat().st_size if path.is_file() else 0
        file_rows.append((rel, sha, f.get("lang", "unknown"), project_id, size))
    if file_rows:
        conn.executemany(
            "INSERT OR REPLACE INTO files VALUES (?, ?, ?, ?, ?)",
            file_rows,
        )

    sym_rows = []
    for s in symbols:
        sid = _resolve_symbol_id(s, scip_lookup)
        if not sid:
            continue
        sym_rows.append(
            (
                sid,
                sid,
                s["kind"],
                s["file"],
                s["range"][0],
                s["range"][1],
                None,
                s.get("name"),
            )
        )
    if sym_rows:
        conn.executemany(
            "INSERT OR REPLACE INTO symbols VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            sym_rows,
        )

    xref_rows = []
    for x in xrefs:
        xref_rows.append(
            (
                x.get("callerSyntheticId"),
                None,  # callee_id resolved in a later pass once symbols exist
                x["kind"],
                x.get("file"),
                x.get("line"),
            )
        )
    if xref_rows:
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?)",
            xref_rows,
        )
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_index_duckdb.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/index/duckdb_ingest.py tests/test_index_duckdb.py
git commit -m "feat(index): bulk ingest AST + scip lookups into duckdb"
```

---

## Task 11: Wire AST + SCIP + ingestion into `prep`

**Files:**
- Modify: `ai_codescan/cli.py`
- Add: `ai_codescan/prep.py` (orchestrator extracted out of `cli.py` to keep cli focused)

- [ ] **Step 1: Extract `prep` orchestrator**

`ai_codescan/prep.py`:

```python
"""End-to-end ``prep`` orchestration."""

from __future__ import annotations

import logging
from pathlib import Path

import duckdb

from ai_codescan.ast.runner import AstJob, run_jobs
from ai_codescan.config import compute_repo_id
from ai_codescan.index.duckdb_ingest import ingest as duckdb_ingest
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.index.scip import build_scip_index
from ai_codescan.repo_md import render_repo_md
from ai_codescan.snapshot import SnapshotResult, take_snapshot
from ai_codescan.stack_detect import Project, ProjectKind, detect_projects

log = logging.getLogger(__name__)


def _files_for_project(snapshot_root: Path, project: Project) -> tuple[list[Path], list[Path]]:
    base = snapshot_root / project.base_path
    ts = [
        p
        for p in base.rglob("*")
        if p.is_file()
        and p.suffix in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
        and "node_modules" not in p.parts
    ]
    html = [
        p
        for p in base.rglob("*")
        if p.is_file() and p.suffix in {".html", ".htm"} and "node_modules" not in p.parts
    ]
    return ts, html


def _ast_jobs_for_project(snapshot_root: Path, project: Project) -> list[AstJob]:
    base = snapshot_root / project.base_path
    ts_files, html_files = _files_for_project(snapshot_root, project)
    jobs: list[AstJob] = []
    if ts_files:
        tsconfig = base / "tsconfig.json"
        jobs.append(
            AstJob(
                kind="ts",
                project_root=base,
                files=ts_files,
                tsconfig=tsconfig if tsconfig.is_file() else None,
            )
        )
    if html_files:
        jobs.append(AstJob(kind="html", project_root=base, files=html_files))
    return jobs


def _build_scip_lookup(snapshot_root: Path, projects: list[Project], cache_dir: Path) -> dict:
    lookup: dict = {}
    for project in projects:
        if project.kind is not ProjectKind.NODE or "typescript" not in project.languages:
            continue
        try:
            result = build_scip_index(
                snapshot_root / project.base_path,
                cache_dir=cache_dir,
                project_id=f"{project.name}-{project.base_path.as_posix().replace('/', '_')}",
            )
        except (RuntimeError, OSError) as exc:
            log.warning("scip index failed for %s: %s", project.name, exc)
            continue
        for doc in result.iter_documents():
            file = (snapshot_root / project.base_path / doc.relative_path).as_posix()
            for occ in doc.occurrences:
                start = occ.range[0] + 1
                end = occ.range[2] + 1 if len(occ.range) >= 3 else start
                if occ.symbol:
                    lookup[(file, start, end)] = f"scip:{occ.symbol}"
    return lookup


def run_prep(
    target: Path,
    *,
    cache_root: Path,
    commit: str | None = None,
) -> tuple[SnapshotResult, Path]:
    """Snapshot, detect, AST, SCIP, ingest. Returns the snapshot result and the duckdb path."""
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

    conn.close()
    return snap, db_path
```

- [ ] **Step 2: Update `cli.py` to call the orchestrator**

In `ai_codescan/cli.py`, replace the `prep` function body with:

```python
@app.command()
def prep(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Target repo to scan.")],
    commit: _CommitOption = None,
) -> None:
    """Snapshot, detect, AST, SCIP, and populate the DuckDB index."""
    from ai_codescan.prep import run_prep

    if not target.is_dir():
        typer.echo(f"Target is not a directory: {target}", err=True)
        raise typer.Exit(code=2)

    cache_root: Path = ctx.obj["cache_root"]
    quiet: bool = ctx.obj["quiet"]
    snap, db_path = run_prep(target, cache_root=cache_root, commit=commit)
    if not quiet:
        status_word = "skipped" if snap.skipped else "took"
        commit_label = f" @ {snap.commit_sha[:8]}" if snap.commit_sha else ""
        typer.echo(f"snapshot {status_word} ({snap.method}){commit_label}")
        typer.echo(f"index at {db_path}")
```

- [ ] **Step 3: Update tests**

Existing CLI tests in `tests/test_cli.py` still pass (snapshot + repo.md still produced). Add a new test:

```python
@pytest.mark.integration
def test_prep_populates_duckdb(tmp_path: Path, fixtures_dir: Path) -> None:
    import duckdb as _duckdb

    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-react")],
    )
    db_path = next((cache.iterdir().__next__() / "index.duckdb",))
    conn = _duckdb.connect(str(db_path))
    n_files = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    n_symbols = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
    assert n_files >= 1
    assert n_symbols >= 1
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: all green (existing + new).

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/prep.py ai_codescan/cli.py tests/test_cli.py
git commit -m "feat(cli): wire ast + scip + duckdb ingest into prep"
```

---

## Task 12: `query` and `flows --from / --to` subcommands

**Files:**
- Modify: `ai_codescan/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Failing tests**

Append to `tests/test_cli.py`:

```python
@pytest.mark.integration
def test_query_subcommand_returns_rows(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    result = runner.invoke(
        app,
        [
            "--cache-dir", str(cache),
            "query", "--repo-id", repo_id,
            "SELECT COUNT(*) AS n FROM symbols",
        ],
    )
    assert result.exit_code == 0
    assert "n" in result.stdout


@pytest.mark.integration
def test_flows_subcommand_handles_empty_db(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "flows", "--repo-id", repo_id, "--from", "anything"],
    )
    assert result.exit_code == 0
    assert "no flows" in result.stdout.lower() or result.stdout.strip() == ""
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: 2 failures.

- [ ] **Step 3: Implement subcommands**

In `ai_codescan/cli.py`:

```python
@app.command()
def query(
    ctx: typer.Context,
    sql: Annotated[str, typer.Argument(help="SQL to run against the repo's index.duckdb.")],
    repo_id: Annotated[str, typer.Option("--repo-id", help="Which cached repo.")] = "",
) -> None:
    """Run an arbitrary read-only SQL against a cached repo's index."""
    import duckdb as _duckdb

    cache_root: Path = ctx.obj["cache_root"]
    if not repo_id:
        repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
        if len(repos) != 1:
            typer.echo("Specify --repo-id (multiple cached repos exist).", err=True)
            raise typer.Exit(code=1)
        repo_id = repos[0]
    db = cache_root / repo_id / "index.duckdb"
    conn = _duckdb.connect(str(db), read_only=True)
    rows = conn.execute(sql).fetchdf()
    typer.echo(rows.to_string(index=False) if not rows.empty else "(no rows)")


@app.command()
def flows(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    from_symbol: Annotated[str, typer.Option("--from")] = "",
    to_symbol: Annotated[str, typer.Option("--to")] = "",
) -> None:
    """List flows reaching/from a symbol via the navigation views."""
    import duckdb as _duckdb

    if bool(from_symbol) == bool(to_symbol):
        typer.echo("Specify exactly one of --from or --to.", err=True)
        raise typer.Exit(code=1)

    cache_root: Path = ctx.obj["cache_root"]
    if not repo_id:
        repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
        if len(repos) != 1:
            typer.echo("Specify --repo-id.", err=True)
            raise typer.Exit(code=1)
        repo_id = repos[0]

    db = cache_root / repo_id / "index.duckdb"
    conn = _duckdb.connect(str(db), read_only=True)
    if from_symbol:
        rows = conn.execute(
            "SELECT * FROM v_sources_to_sinks WHERE source_symbol_id = ?",
            [from_symbol],
        ).fetchdf()
    else:
        rows = conn.execute(
            "SELECT * FROM v_sinks_from_sources WHERE sink_symbol_id = ?",
            [to_symbol],
        ).fetchdf()
    if rows.empty:
        typer.echo("no flows")
        return
    typer.echo(rows.to_string(index=False))
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/cli.py tests/test_cli.py
git commit -m "feat(cli): add query and flows subcommands"
```

---

## Task 13: Quality gate, smoke test, milestone tag

- [ ] **Step 1: Run the gate**

```bash
make check
```

Fix any warnings inline.

- [ ] **Step 2: Smoke test**

```bash
uv run ai-codescan prep /tmp/tmp-express
uv run ai-codescan query "SELECT COUNT(*) FROM symbols"
uv run ai-codescan query "SELECT kind, COUNT(*) FROM symbols GROUP BY kind"
```

Expected: non-zero counts.

- [ ] **Step 3: Update README**

Append to `README.md` under `## Phase 1A status`:

```markdown
## Phase 1B status

`prep` now also runs the AST extractor (ts-morph + parse5 + tree-sitter), builds a SCIP index, and populates `index.duckdb`. New subcommands: `query`, `flows --from/--to`. Install `scip-typescript` globally first:

\`\`\`bash
npm i -g @sourcegraph/scip-typescript
\`\`\`
```

- [ ] **Step 4: Commit + tag**

```bash
git add README.md
git commit -m "docs: phase 1B status"
git tag -a phase-1b -m "Phase 1B: AST + SCIP + DuckDB symbols"
```

---

## Self-review

| Spec section | Implemented in |
|---|---|
| §5.3 AST (ts/html/treesitter) | Tasks 3–7 |
| §5.4 SCIP indexer | Task 9 |
| §5.6 DuckDB schema (subset: files, symbols, xrefs, views) | Tasks 8 + 10 |
| §7 CLI: `query`, `flows --from/--to` | Task 12 |
| §11.4 reproducibility | Task 1 (pinned versions) + Task 3 (pinned Node deps) |

Deferred to 1C–1E: taint_sources/sinks/flows population (1C), entrypoints (1D), sidecars + views (1D), nominator + gates (1E), bug-class taxonomy (1E).

No placeholders. Type names consistent across tasks. CLI flag names match spec (`--repo-id`, `--from`, `--to`).
