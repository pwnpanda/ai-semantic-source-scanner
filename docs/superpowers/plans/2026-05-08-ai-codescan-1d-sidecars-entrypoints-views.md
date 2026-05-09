# AI_Codescan 1D — Sidecars + Entrypoints + Views Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Project the DuckDB index into the artefacts an LLM agent will consume: per-file sidecar JSONL records, an `entrypoints.md` summary listing every place user input enters the system, and on-demand annotated source views that show flows inline. After this plan, the wide nominator (Plan 1E) has the inputs it needs.

**Architecture:** All three artefacts are *projections* of `index.duckdb` — never the source of truth. Detection of HTTP routes, listeners, cron jobs, CLI argv usage, and message consumers is heuristic and framework-aware (Express, Fastify, Nest, Koa, Hapi, Next.js API routes, plus generic CLI/event-emitter patterns). Sidecars are append-only JSONL; views are markdown rendered from the same data the LLM agent will see.

**Tech Stack:** Python only — no new runtime deps. Reuses ts-morph + parse5 output already in DuckDB.

**Reference spec:** §4.3 Layer 2 (sidecars) + Layer 4 (views), §5.7, §5.8, §6.3 entrypoints kinds, §7 (`view`, `entrypoints` subcommands).

**Depends on:** Plans 1A + 1B + 1C complete. `index.duckdb` populated with files / symbols / xrefs / sources / sinks / flows.

---

## File Structure (added)

```
AI_Analysis/
├── ai_codescan/
│   ├── entrypoints/
│   │   ├── __init__.py
│   │   ├── detectors.py              # framework-specific detectors
│   │   ├── render.py                 # entrypoints.md renderer
│   │   └── ingest.py                 # populate `entrypoints` table
│   ├── sidecars.py                   # per-file enrich.jsonl emitter
│   └── views.py                      # annotated source view
└── tests/
    ├── test_entrypoints_detect.py
    ├── test_entrypoints_render.py
    ├── test_sidecars.py
    └── test_views.py
```

---

## Task 1: Entrypoint detectors

**Files:**
- Create: `ai_codescan/entrypoints/__init__.py`
- Create: `ai_codescan/entrypoints/detectors.py`
- Test: `tests/test_entrypoints_detect.py`

Detectors operate on AST records (the same JSONL the worker emitted before ingestion). Each detector returns `Entrypoint(symbol_id, kind, signature)` records.

- [ ] **Step 1: Failing tests**

`tests/test_entrypoints_detect.py`:

```python
"""Tests for ai_codescan.entrypoints.detectors."""

from ai_codescan.entrypoints.detectors import detect_entrypoints


def test_express_route_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/server.js",
            "line": 5,
            "calleeText": "app.get",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    kinds = [e.kind for e in eps]
    assert "http_route" in kinds


def test_fastify_route_detected() -> None:
    xrefs = [{"type": "xref", "kind": "call", "file": "/abs/x.ts", "line": 3, "calleeText": "fastify.post"}]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_event_listener_detected() -> None:
    xrefs = [{"type": "xref", "kind": "call", "file": "/abs/x.ts", "line": 9, "calleeText": "emitter.on"}]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "listener" for e in eps)


def test_cli_argv_use_detected() -> None:
    symbols = [
        {
            "type": "symbol",
            "file": "/abs/cli.js",
            "kind": "variable",
            "name": "args",
            "range": [1, 1],
            "syntheticId": "synthetic:111",
        }
    ]
    xrefs = [{"type": "xref", "kind": "call", "file": "/abs/cli.js", "line": 2, "calleeText": "process.argv.slice"}]
    eps = detect_entrypoints(xrefs=xrefs, symbols=symbols)
    assert any(e.kind == "cli" for e in eps)


def test_no_match_yields_empty() -> None:
    eps = detect_entrypoints(xrefs=[], symbols=[])
    assert eps == []
```

- [ ] **Step 2: Implement detectors**

`ai_codescan/entrypoints/__init__.py`: empty.

`ai_codescan/entrypoints/detectors.py`:

```python
"""Heuristic entrypoint detection for JS/TS frameworks."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

EntrypointKind = str  # 'http_route' | 'listener' | 'cron' | 'cli' | 'message_consumer'


@dataclass(frozen=True, slots=True)
class Entrypoint:
    symbol_id: str | None
    kind: EntrypointKind
    signature: str
    file: str
    line: int


_HTTP_ROUTE = re.compile(
    r"\b(?:app|router|fastify|server|api)\.(?:get|post|put|patch|delete|options|all|use)$",
    re.IGNORECASE,
)
_NEST_ROUTE_DECORATOR = re.compile(r"@(?:Get|Post|Put|Patch|Delete|All)\(")
_LISTENER = re.compile(r"\.(?:on|once|addListener|addEventListener)$")
_CRON = re.compile(r"\b(?:cron|node-cron|node-schedule)\.(?:schedule|job)$|@Cron\(")
_CLI_ARGV = re.compile(r"\bprocess\.argv\b")
_QUEUE_CONSUMER = re.compile(
    r"\b(?:queue|worker|consumer)\.(?:process|consume|subscribe)$|"
    r"\b(?:bullmq|amqplib|kafkajs)\..*?\.(?:process|consume|subscribe)$",
    re.IGNORECASE,
)


def _classify_callee(callee: str) -> EntrypointKind | None:
    if _HTTP_ROUTE.search(callee):
        return "http_route"
    if _LISTENER.search(callee):
        return "listener"
    if _CRON.search(callee):
        return "cron"
    if _CLI_ARGV.search(callee):
        return "cli"
    if _QUEUE_CONSUMER.search(callee):
        return "message_consumer"
    return None


def detect_entrypoints(
    *,
    xrefs: Iterable[dict[str, Any]],
    symbols: Iterable[dict[str, Any]],
) -> list[Entrypoint]:
    """Return all entrypoints found across ``xrefs`` and ``symbols``."""
    out: list[Entrypoint] = []
    for x in xrefs:
        if x.get("kind") != "call":
            continue
        callee = (x.get("calleeText") or "").strip()
        kind = _classify_callee(callee)
        if not kind:
            continue
        out.append(
            Entrypoint(
                symbol_id=x.get("callerSyntheticId"),
                kind=kind,
                signature=callee,
                file=x.get("file", ""),
                line=int(x.get("line", 0)),
            )
        )
    return out
```

- [ ] **Step 3: Run tests**

```bash
uv run pytest tests/test_entrypoints_detect.py -v
```

Expected: 5 passed.

- [ ] **Step 4: Commit**

```bash
git add ai_codescan/entrypoints/__init__.py ai_codescan/entrypoints/detectors.py tests/test_entrypoints_detect.py
git commit -m "feat(entrypoints): heuristic detectors for routes/listeners/cli/queues"
```

---

## Task 2: Entrypoint ingestion + `entrypoints.md` rendering

**Files:**
- Create: `ai_codescan/entrypoints/ingest.py`
- Create: `ai_codescan/entrypoints/render.py`
- Test: `tests/test_entrypoints_render.py`

- [ ] **Step 1: Failing tests**

`tests/test_entrypoints_render.py`:

```python
"""Tests for entrypoint ingestion + rendering."""

from pathlib import Path

import duckdb

from ai_codescan.entrypoints.detectors import Entrypoint
from ai_codescan.entrypoints.ingest import ingest_entrypoints
from ai_codescan.entrypoints.render import render_entrypoints_md
from ai_codescan.index.duckdb_schema import apply_schema


def test_ingest_writes_rows(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    eps = [
        Entrypoint(symbol_id=None, kind="http_route", signature="app.get", file="/a.js", line=5),
        Entrypoint(symbol_id=None, kind="listener", signature="bus.on", file="/b.ts", line=9),
    ]
    ingest_entrypoints(conn, eps)
    rows = conn.execute("SELECT kind, signature FROM entrypoints ORDER BY kind").fetchall()
    assert rows == [("http_route", "app.get"), ("listener", "bus.on")]


def test_render_groups_by_kind() -> None:
    eps = [
        Entrypoint(symbol_id=None, kind="http_route", signature="app.get", file="/a.js", line=5),
        Entrypoint(symbol_id=None, kind="http_route", signature="app.post", file="/a.js", line=7),
        Entrypoint(symbol_id=None, kind="listener", signature="bus.on", file="/b.ts", line=9),
    ]
    md = render_entrypoints_md(target_name="t", entrypoints=eps)
    assert "# Entrypoints: t" in md
    assert "## http_route" in md and "## listener" in md
    http_idx = md.index("## http_route")
    listener_idx = md.index("## listener")
    assert http_idx < listener_idx


def test_render_handles_empty() -> None:
    md = render_entrypoints_md(target_name="t", entrypoints=[])
    assert "No entrypoints detected" in md
```

- [ ] **Step 2: Implement ingestion + rendering**

`ai_codescan/entrypoints/ingest.py`:

```python
"""Ingest detected entrypoints into the DuckDB ``entrypoints`` table."""

from __future__ import annotations

from collections.abc import Iterable

import duckdb

from ai_codescan.entrypoints.detectors import Entrypoint


def ingest_entrypoints(
    conn: duckdb.DuckDBPyConnection,
    entrypoints: Iterable[Entrypoint],
) -> int:
    rows = [(e.symbol_id, e.kind, e.signature) for e in entrypoints]
    if not rows:
        return 0
    conn.executemany("INSERT INTO entrypoints VALUES (?, ?, ?)", rows)
    return len(rows)
```

`ai_codescan/entrypoints/render.py`:

```python
"""Render the ``entrypoints.md`` summary."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from ai_codescan.entrypoints.detectors import Entrypoint

_KIND_ORDER = ("http_route", "listener", "cron", "cli", "message_consumer")


def render_entrypoints_md(*, target_name: str, entrypoints: Iterable[Entrypoint]) -> str:
    eps = list(entrypoints)
    lines = [f"# Entrypoints: {target_name}", ""]
    if not eps:
        lines.append("No entrypoints detected.")
        lines.append("")
        return "\n".join(lines)
    by_kind: dict[str, list[Entrypoint]] = defaultdict(list)
    for e in eps:
        by_kind[e.kind].append(e)
    for kind in _KIND_ORDER:
        if kind not in by_kind:
            continue
        lines.append(f"## {kind}")
        lines.append("")
        for e in sorted(by_kind[kind], key=lambda x: (x.file, x.line, x.signature)):
            lines.append(f"- `{e.signature}` at `{e.file}:{e.line}`")
        lines.append("")
    return "\n".join(lines)
```

- [ ] **Step 3: Run tests**

```bash
uv run pytest tests/test_entrypoints_render.py -v
```

Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add ai_codescan/entrypoints/ingest.py ai_codescan/entrypoints/render.py tests/test_entrypoints_render.py
git commit -m "feat(entrypoints): ingest into duckdb + render entrypoints.md"
```

---

## Task 3: Sidecar JSONL emitter (`sidecars.py`)

**Files:**
- Create: `ai_codescan/sidecars.py`
- Test: `tests/test_sidecars.py`

Per-file sidecar contains the symbols, sources, sinks, flows, and entrypoints anchored to that file. One JSONL record per item. Path: `<snapshot_dir>/<relpath>.enrich.jsonl`.

- [ ] **Step 1: Failing tests**

`tests/test_sidecars.py`:

```python
"""Tests for ai_codescan.sidecars."""

import json
from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.sidecars import emit_sidecars


def _seed(conn: duckdb.DuckDBPyConnection, file: str) -> None:
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [file])
    conn.execute(
        "INSERT INTO symbols VALUES (?, 'sym1', 'function', ?, 1, 5, NULL, 'handler')",
        ["S1", file],
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', 'S1', 'http.body', 'name', ?)",
        [f"{file}:2"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', 'S1', 'sql.exec', 'pg', 'template-literal', '[]')",
    )
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'codeql', '[]', '/sarif', 'definite')"
    )
    conn.execute("INSERT INTO entrypoints VALUES ('S1', 'http_route', 'app.post')")


def test_emit_sidecar_per_file_with_records(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    file_abs = (tmp_path / "src" / "handler.ts").as_posix()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "handler.ts").write_text("export const handler = () => {};\n")
    _seed(conn, file_abs)

    n = emit_sidecars(conn, snapshot_root=tmp_path)
    assert n == 1
    sidecar = tmp_path / "src" / "handler.ts.enrich.jsonl"
    assert sidecar.is_file()
    records = [json.loads(line) for line in sidecar.read_text().splitlines() if line.strip()]
    kinds = {r["kind"] for r in records}
    assert {"symbol", "source", "sink", "flow", "entrypoint"} <= kinds


def test_emit_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    file_abs = (tmp_path / "f.ts").as_posix()
    (tmp_path / "f.ts").write_text("//\n")
    _seed(conn, file_abs)
    emit_sidecars(conn, snapshot_root=tmp_path)
    first = (tmp_path / "f.ts.enrich.jsonl").read_text()
    emit_sidecars(conn, snapshot_root=tmp_path)
    second = (tmp_path / "f.ts.enrich.jsonl").read_text()
    assert first == second
```

- [ ] **Step 2: Implement**

`ai_codescan/sidecars.py`:

```python
"""Emit per-file sidecar JSONL records derived from the DuckDB index."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb


def _records_for_file(conn: duckdb.DuckDBPyConnection, file: str) -> list[dict]:
    out: list[dict] = []

    for sym_id, kind, range_start, range_end, display_name in conn.execute(
        "SELECT id, kind, range_start, range_end, display_name FROM symbols WHERE file = ?",
        [file],
    ).fetchall():
        out.append(
            {
                "id": sym_id,
                "kind": "symbol",
                "sym_kind": kind,
                "range": [range_start, range_end],
                "name": display_name,
            }
        )

    for tid, klass, key, evidence_loc in conn.execute(
        "SELECT tid, class, key, evidence_loc FROM taint_sources WHERE evidence_loc LIKE ?",
        [f"{file}:%"],
    ).fetchall():
        out.append(
            {
                "id": tid,
                "kind": "source",
                "class": klass,
                "key": key,
                "loc": evidence_loc,
            }
        )

    for sid, klass, lib, parameterization in conn.execute(
        """
        SELECT s.sid, s.class, s.lib, s.parameterization
        FROM taint_sinks s
        JOIN symbols sym ON sym.id = s.symbol_id
        WHERE sym.file = ?
        """,
        [file],
    ).fetchall():
        out.append(
            {
                "id": sid,
                "kind": "sink",
                "class": klass,
                "lib": lib,
                "parameterization": parameterization,
            }
        )

    for fid, tid, sid, cwe, engine in conn.execute(
        """
        SELECT f.fid, f.tid, f.sid, f.cwe, f.engine
        FROM flows f
        JOIN taint_sources s ON s.tid = f.tid
        WHERE s.evidence_loc LIKE ?
        """,
        [f"{file}:%"],
    ).fetchall():
        out.append({"id": fid, "kind": "flow", "tid": tid, "sid": sid, "cwe": cwe, "engine": engine})

    for sym_id, kind, sig in conn.execute(
        """
        SELECT e.symbol_id, e.kind, e.signature
        FROM entrypoints e
        LEFT JOIN symbols sym ON sym.id = e.symbol_id
        WHERE sym.file = ? OR e.symbol_id IS NULL
        """,
        [file],
    ).fetchall():
        out.append({"kind": "entrypoint", "ep_kind": kind, "signature": sig, "symbol_id": sym_id})

    return out


def emit_sidecars(
    conn: duckdb.DuckDBPyConnection,
    *,
    snapshot_root: Path,
) -> int:
    """Write one ``<file>.enrich.jsonl`` per file in the index. Returns count emitted."""
    files = [row[0] for row in conn.execute("SELECT path FROM files").fetchall()]
    written = 0
    for file in files:
        records = _records_for_file(conn, file)
        if not records:
            continue
        target = Path(file + ".enrich.jsonl")
        if not target.is_absolute():
            target = snapshot_root / file
            target = target.with_suffix(target.suffix + ".enrich.jsonl")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, separators=(",", ":")))
                f.write("\n")
        tmp.replace(target)
        written += 1
    return written
```

- [ ] **Step 3: Run tests**

```bash
uv run pytest tests/test_sidecars.py -v
```

Expected: 2 passed.

- [ ] **Step 4: Commit**

```bash
git add ai_codescan/sidecars.py tests/test_sidecars.py
git commit -m "feat(sidecars): emit per-file enrich.jsonl from duckdb"
```

---

## Task 4: Annotated source views (`views.py`)

**Files:**
- Create: `ai_codescan/views.py`
- Test: `tests/test_views.py`

Renders a markdown view of one source file: code-fenced source plus inline annotations. The view is generated, not stored as truth.

- [ ] **Step 1: Failing tests**

`tests/test_views.py`:

```python
"""Tests for ai_codescan.views."""

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.views import render_file_view


def test_render_view_includes_annotations(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    file_abs = (tmp_path / "h.ts").as_posix()
    (tmp_path / "h.ts").write_text(
        "export const h = (req, res) => {\n  const id = req.query.id;\n  res.send(id);\n};\n"
    )
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [file_abs])
    conn.execute(
        "INSERT INTO symbols VALUES ('S1', 'sym', 'function', ?, 1, 4, NULL, 'h')",
        [file_abs],
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', 'S1', 'http.query', 'id', ?)",
        [f"{file_abs}:2"],
    )

    md = render_file_view(conn, file=file_abs)
    assert "# View:" in md
    assert "```typescript" in md or "```ts" in md
    assert "T1" in md
    assert "h.ts" in md


def test_render_view_for_unknown_file_returns_marker(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    md = render_file_view(conn, file=str(tmp_path / "missing.ts"))
    assert "No data for" in md
```

- [ ] **Step 2: Implement**

`ai_codescan/views.py`:

```python
"""Render annotated source views from the DuckDB index."""

from __future__ import annotations

from pathlib import Path

import duckdb


def _lang_fence(file: str) -> str:
    if file.endswith((".ts", ".tsx")):
        return "typescript"
    if file.endswith((".js", ".jsx", ".mjs", ".cjs")):
        return "javascript"
    if file.endswith((".html", ".htm")):
        return "html"
    return ""


def _annotations_by_line(conn: duckdb.DuckDBPyConnection, file: str) -> dict[int, list[str]]:
    by_line: dict[int, list[str]] = {}

    for sym_id, range_start, display_name in conn.execute(
        "SELECT id, range_start, display_name FROM symbols WHERE file = ?",
        [file],
    ).fetchall():
        by_line.setdefault(range_start, []).append(f"[{sym_id}] symbol {display_name}")

    for tid, evidence in conn.execute(
        "SELECT tid, evidence_loc FROM taint_sources WHERE evidence_loc LIKE ?",
        [f"{file}:%"],
    ).fetchall():
        line = int(evidence.rsplit(":", 1)[1])
        by_line.setdefault(line, []).append(f"[{tid}] SOURCE")

    for fid, tid, sid, cwe in conn.execute(
        """
        SELECT f.fid, f.tid, f.sid, f.cwe
        FROM flows f
        JOIN taint_sources s ON s.tid = f.tid
        WHERE s.evidence_loc LIKE ?
        """,
        [f"{file}:%"],
    ).fetchall():
        evidence = conn.execute(
            "SELECT evidence_loc FROM taint_sources WHERE tid = ?", [tid]
        ).fetchone()
        if not evidence:
            continue
        line = int(evidence[0].rsplit(":", 1)[1])
        by_line.setdefault(line, []).append(f"FLOW {fid} ({cwe})")

    return by_line


def render_file_view(conn: duckdb.DuckDBPyConnection, *, file: str) -> str:
    """Return a markdown view of ``file`` with line-anchored annotations."""
    row = conn.execute("SELECT path FROM files WHERE path = ?", [file]).fetchone()
    if not row:
        return f"No data for {file} in the index."
    fp = Path(file)
    if not fp.is_file():
        return f"No data for {file} (file missing)."
    lang = _lang_fence(file)
    text = fp.read_text(encoding="utf-8")
    annotations = _annotations_by_line(conn, file)

    out = [f"# View: {fp.name}", "", f"`{file}`", "", f"```{lang}"]
    for idx, line in enumerate(text.splitlines(), 1):
        markers = annotations.get(idx)
        suffix = f"  // {' | '.join(markers)}" if markers else ""
        out.append(f"{line}{suffix}")
    out.append("```")
    return "\n".join(out) + "\n"
```

- [ ] **Step 3: Run tests**

```bash
uv run pytest tests/test_views.py -v
```

Expected: 2 passed.

- [ ] **Step 4: Commit**

```bash
git add ai_codescan/views.py tests/test_views.py
git commit -m "feat(views): annotated source view rendered from duckdb"
```

---

## Task 5: Wire entrypoints + sidecars into `prep`; add `view` and `entrypoints` CLI

**Files:**
- Modify: `ai_codescan/prep.py`
- Modify: `ai_codescan/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Extend `prep.py` to compute entrypoints and emit sidecars**

In `ai_codescan/prep.py`, augment the per-project loop where AST records are collected. After ingesting xrefs, run the entrypoint detector and ingest its results. After all projects are processed, emit sidecars and `entrypoints.md`.

Add imports at the top:

```python
from ai_codescan.entrypoints.detectors import detect_entrypoints
from ai_codescan.entrypoints.ingest import ingest_entrypoints
from ai_codescan.entrypoints.render import render_entrypoints_md
from ai_codescan.sidecars import emit_sidecars
```

Inside the `for project in projects:` loop in `run_prep`, after `duckdb_ingest(...)`, add:

```python
        entries = detect_entrypoints(xrefs=xrefs, symbols=symbols)
        ingest_entrypoints(conn, entries)
```

After the loop (still inside `run_prep`, before `if engine == "codeql":`), build the cumulative entrypoints list for rendering:

```python
    all_entries_rows = conn.execute(
        "SELECT symbol_id, kind, signature FROM entrypoints"
    ).fetchall()
    all_entries = []
    from ai_codescan.entrypoints.detectors import Entrypoint as _E
    for sym_id, kind, sig in all_entries_rows:
        all_entries.append(_E(symbol_id=sym_id, kind=kind, signature=sig, file="", line=0))
    (repo_dir / "entrypoints.md").write_text(
        render_entrypoints_md(target_name=target.name, entrypoints=all_entries),
        encoding="utf-8",
    )
```

After `_run_codeql_for_projects(...)` and before `conn.close()`, emit sidecars:

```python
    emit_sidecars(conn, snapshot_root=snap.snapshot_dir)
```

- [ ] **Step 2: Add `view` and `entrypoints` CLI subcommands**

In `ai_codescan/cli.py`:

```python
@app.command()
def view(
    ctx: typer.Context,
    file: Annotated[str, typer.Option("--file", help="Absolute path of a file in the snapshot.")] = "",
    symbol: Annotated[str, typer.Option("--symbol", help="Symbol id to centre the view on.")] = "",
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
) -> None:
    """Render an annotated source view to stdout."""
    import duckdb as _duckdb

    if bool(file) == bool(symbol):
        typer.echo("Specify exactly one of --file or --symbol.", err=True)
        raise typer.Exit(code=1)

    cache_root: Path = ctx.obj["cache_root"]
    if not repo_id:
        repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
        if len(repos) != 1:
            typer.echo("Specify --repo-id.", err=True)
            raise typer.Exit(code=1)
        repo_id = repos[0]
    db_path = cache_root / repo_id / "index.duckdb"
    conn = _duckdb.connect(str(db_path), read_only=True)

    if symbol:
        row = conn.execute("SELECT file FROM symbols WHERE id = ?", [symbol]).fetchone()
        if not row:
            typer.echo(f"unknown symbol id: {symbol}", err=True)
            raise typer.Exit(code=1)
        file = row[0]

    from ai_codescan.views import render_file_view

    typer.echo(render_file_view(conn, file=file))


@app.command()
def entrypoints(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
) -> None:
    """Print the cached ``entrypoints.md``."""
    cache_root: Path = ctx.obj["cache_root"]
    if not repo_id:
        repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
        if len(repos) != 1:
            typer.echo("Specify --repo-id.", err=True)
            raise typer.Exit(code=1)
        repo_id = repos[0]
    md_path = cache_root / repo_id / "entrypoints.md"
    if not md_path.is_file():
        typer.echo("No entrypoints.md yet — run `prep` first.", err=True)
        raise typer.Exit(code=1)
    typer.echo(md_path.read_text(encoding="utf-8"))
```

- [ ] **Step 3: Tests**

Append to `tests/test_cli.py`:

```python
@pytest.mark.integration
def test_prep_emits_entrypoints_md(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    ep = (cache / repo_id / "entrypoints.md").read_text()
    assert "Entrypoints:" in ep


@pytest.mark.integration
def test_view_command_renders_for_known_file(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    snap_root = cache / repo_id / "source"
    server_js = next(snap_root.rglob("server.js"))
    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "view", "--file", str(server_js), "--repo-id", repo_id],
    )
    assert result.exit_code == 0
    assert "View:" in result.stdout
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: green.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/prep.py ai_codescan/cli.py tests/test_cli.py
git commit -m "feat(cli): wire entrypoints + sidecars; add view and entrypoints subcommands"
```

---

## Task 6: Quality gate, smoke test, milestone tag

- [ ] **Step 1: Gate**

```bash
make check
```

- [ ] **Step 2: Smoke test**

```bash
uv run ai-codescan prep /tmp/tmp-express
uv run ai-codescan entrypoints
ls ~/.ai_codescan/repos/tmp-express-*/source/**/*.enrich.jsonl 2>/dev/null | head
uv run ai-codescan view --file $(find ~/.ai_codescan/repos/tmp-express-*/source -name '*.js' | head -1)
```

- [ ] **Step 3: README + tag**

Append to `README.md`:

```markdown
## Phase 1D status

`prep` now derives `entrypoints.md`, emits per-file `*.enrich.jsonl` sidecars, and `view`/`entrypoints` subcommands surface them.
```

```bash
git add README.md
git commit -m "docs: phase 1D status"
git tag -a phase-1d -m "Phase 1D: sidecars, entrypoints, views"
```

---

## Self-review

| Spec section | Implemented in |
|---|---|
| §4.3 Layer 2 sidecars | Task 3 |
| §4.3 Layer 4 annotated views | Task 4 |
| §5.7 sidecars module | Task 3 |
| §5.8 views module | Task 4 |
| §6.3 entrypoints (kinds list) | Task 1 |
| §7 `view`, `entrypoints` subcommands | Task 5 |

Deferred to 1E: nominator, gate-1, the `run` super-command, full taxonomy with `needs_semantic` classes.

No placeholders. Every CLI flag tested. Sidecar paths align to spec §8 (`<cache>/source/**/*.enrich.jsonl`). Views live in `<cache>/views/` only when `--save` is added later — for now they go to stdout.
