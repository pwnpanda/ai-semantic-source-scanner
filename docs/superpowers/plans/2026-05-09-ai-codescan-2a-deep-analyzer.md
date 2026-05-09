# AI_Codescan 2A — Deep Analyser + Gate 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development` or `superpowers:executing-plans`. Step checkboxes use `- [ ]`.

**Goal:** Take the y-marked nominations from Phase 1's Gate 1 and run an Opus sub-agent per finding to produce per-finding markdown reports under `findings/<id>.md` with frontmatter status `unverified`. Add `gate-2` HITL pruning step.

**Architecture:** A new `analyzer.py` reads `nominations.md` for accepted items, extracts a minimal slice (LLMxCPG pattern: source/sink/intermediate ±5 lines), spawns one Opus sub-agent per finding via the existing `llm.py` provider abstraction. Sub-agents emit a markdown finding doc with structured frontmatter. A `findings_queue.md` tracks state with the same atomic-line claim pattern Phase 1 uses.

**Tech Stack:** Python only changes. Reuses Phase 1 modules: `gate.parse_nominations`, `llm.LLMConfig`, `runs.state.RunState`, DuckDB index.

**Reference spec:** `docs/superpowers/specs/2026-05-09-ai-codescan-phase2-design.md` §4.1 + §5 + §6.

**Depends on:** Phase 1 complete.

---

## File Structure (added)

```
ai_codescan/
├── analyzer.py              # orchestrator: queue → sub-agent → finding doc
├── slice.py                 # slice extraction from a flow
├── findings/
│   ├── __init__.py
│   ├── model.py             # Finding dataclass + frontmatter parse/render
│   └── queue.py             # findings_queue.md generator + atomic-line ops
└── skills/deep_analyzer/
    ├── SKILL.md
    ├── prompts/analyzer.md
    └── scripts/loop.sh

tests/
├── test_slice.py
├── test_findings_model.py
├── test_findings_queue.py
├── test_analyzer.py
└── fixtures/sample-flow.json
```

---

## Task 1: Slice extraction (`slice.py`)

**Files:**
- Create: `ai_codescan/slice.py`
- Test: `tests/test_slice.py`

### Step 1: Failing tests

`tests/test_slice.py`:

```python
"""Tests for ai_codescan.slice."""

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.slice import SliceBundle, extract_slice


def _seed(conn: duckdb.DuckDBPyConnection, file: Path, src: str) -> None:
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [file.as_posix()])
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', NULL, 'http.body', 'name', ?)",
        [f"{file.as_posix()}:2"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    steps = '[["%s", 2, 2], ["%s", 5, 5]]' % (file.as_posix(), file.as_posix())
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif', 'definite')",
        [steps],
    )


def test_extract_slice_returns_source_sink_with_context(tmp_path: Path) -> None:
    src = tmp_path / "x.ts"
    src.write_text("// 1\nconst id = req.body.name\n// 3\n// 4\nawait db.query(`x ${id}`)\n// 6\n")
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn, src, src.read_text())

    bundle = extract_slice(conn, flow_id="F1", context_lines=2)

    assert isinstance(bundle, SliceBundle)
    assert bundle.cwe == "CWE-89"
    assert any(step.line == 2 for step in bundle.steps)
    assert any(step.line == 5 for step in bundle.steps)
    # Each step carries ±2 lines of context (clamped to file bounds).
    src_step = next(s for s in bundle.steps if s.line == 2)
    assert "const id = req.body.name" in src_step.code_excerpt
    assert src_step.context_start == 1
    assert src_step.context_end == 4


def test_extract_slice_unknown_flow_returns_none(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    assert extract_slice(conn, flow_id="missing", context_lines=2) is None
```

### Step 2: Implementation

`ai_codescan/slice.py`:

```python
"""Extract a minimal flow slice (LLMxCPG pattern) for an LLM sub-agent."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import duckdb


@dataclass(frozen=True, slots=True)
class SliceStep:
    file: str
    line: int
    context_start: int
    context_end: int
    code_excerpt: str


@dataclass(frozen=True, slots=True)
class SliceBundle:
    flow_id: str
    cwe: str | None
    source_loc: str
    sink_id: str
    steps: list[SliceStep]


def _read_excerpt(file: Path, start: int, end: int) -> str:
    if not file.is_file():
        return ""
    lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[max(0, start - 1) : end])


def extract_slice(
    conn: duckdb.DuckDBPyConnection,
    *,
    flow_id: str,
    context_lines: int = 5,
) -> SliceBundle | None:
    row = conn.execute(
        """
        SELECT f.fid, f.cwe, f.tid, f.sid, f.steps_json, s.evidence_loc
        FROM flows f
        JOIN taint_sources s ON s.tid = f.tid
        WHERE f.fid = ?
        """,
        [flow_id],
    ).fetchone()
    if row is None:
        return None
    fid, cwe, _tid, sid, steps_json, source_loc = row

    raw_steps: list[list] = json.loads(steps_json or "[]")
    steps: list[SliceStep] = []
    for entry in raw_steps:
        if len(entry) < 2:
            continue
        file_str = str(entry[0])
        start_line = int(entry[1])
        ctx_start = max(1, start_line - context_lines)
        ctx_end = start_line + context_lines
        excerpt = _read_excerpt(Path(file_str), ctx_start, ctx_end)
        # Clamp ctx_end to file's last line (proxy: lines counted in excerpt).
        n_lines_kept = len(excerpt.splitlines())
        actual_end = ctx_start + max(0, n_lines_kept - 1)
        steps.append(
            SliceStep(
                file=file_str,
                line=start_line,
                context_start=ctx_start,
                context_end=actual_end,
                code_excerpt=excerpt,
            )
        )

    return SliceBundle(
        flow_id=fid,
        cwe=cwe,
        source_loc=source_loc or "",
        sink_id=sid,
        steps=steps,
    )
```

### Step 3: Run tests + commit

```bash
uv run pytest tests/test_slice.py -v
git add ai_codescan/slice.py tests/test_slice.py
git commit -m "feat(slice): extract flow slice with line context"
```

Expected: 2 passed.

---

## Task 2: Findings model (`findings/model.py`)

**Files:**
- Create: `ai_codescan/findings/__init__.py`
- Create: `ai_codescan/findings/model.py`
- Test: `tests/test_findings_model.py`

### Step 1: Tests

`tests/test_findings_model.py`:

```python
"""Tests for ai_codescan.findings.model."""

from ai_codescan.findings.model import Finding, parse_finding, render_finding


def test_render_then_parse_roundtrips() -> None:
    f = Finding(
        finding_id="F-001",
        nomination_id="N-001",
        flow_id="F1",
        cwe="CWE-89",
        status="unverified",
        title="SQL injection in users.ts:42",
        body="The handler concatenates `req.params.id` into a SQL query.",
    )
    md = render_finding(f)
    parsed = parse_finding(md)
    assert parsed == f


def test_parse_extracts_status_from_frontmatter() -> None:
    md = (
        "---\n"
        "finding_id: F-002\n"
        "nomination_id: N-014\n"
        "flow_id: \"\"\n"
        "cwe: CWE-639\n"
        "status: verified\n"
        'title: "IDOR in /orders/:id"\n'
        "---\n\n"
        "Body text.\n"
    )
    f = parse_finding(md)
    assert f.status == "verified"
    assert f.cwe == "CWE-639"
    assert f.flow_id == ""
```

### Step 2: Implementation

`ai_codescan/findings/__init__.py`: empty.

`ai_codescan/findings/model.py`:

```python
"""Finding dataclass + markdown frontmatter (de)serialisation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import yaml

Status = Literal["unverified", "verified", "rejected", "poc_inconclusive"]


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    nomination_id: str
    flow_id: str
    cwe: str | None
    status: Status
    title: str
    body: str


def render_finding(f: Finding) -> str:
    front = {
        "finding_id": f.finding_id,
        "nomination_id": f.nomination_id,
        "flow_id": f.flow_id,
        "cwe": f.cwe or "",
        "status": f.status,
        "title": f.title,
    }
    return f"---\n{yaml.safe_dump(front, sort_keys=True).strip()}\n---\n\n{f.body}"


def parse_finding(md: str) -> Finding:
    if not md.startswith("---\n"):
        raise ValueError("missing frontmatter")
    end = md.find("\n---\n", 4)
    if end == -1:
        raise ValueError("unterminated frontmatter")
    front_raw = md[4:end]
    body = md[end + 5 :].lstrip("\n")
    front = yaml.safe_load(front_raw) or {}
    return Finding(
        finding_id=str(front.get("finding_id", "")),
        nomination_id=str(front.get("nomination_id", "")),
        flow_id=str(front.get("flow_id", "")),
        cwe=str(front.get("cwe") or "") or None,
        status=str(front.get("status", "unverified")),  # type: ignore[arg-type]
        title=str(front.get("title", "")),
        body=body,
    )
```

### Step 3: Run + commit

```bash
uv run pytest tests/test_findings_model.py -v
git add ai_codescan/findings/__init__.py ai_codescan/findings/model.py tests/test_findings_model.py
git commit -m "feat(findings): finding dataclass + frontmatter (de)serialisation"
```

Expected: 2 passed.

---

## Task 3: Findings queue (`findings/queue.py`)

**Files:**
- Create: `ai_codescan/findings/queue.py`
- Test: `tests/test_findings_queue.py`

### Step 1: Tests

`tests/test_findings_queue.py`:

```python
"""Tests for ai_codescan.findings.queue."""

from pathlib import Path

from ai_codescan.findings.queue import (
    QueueItem,
    accepted_nominations_to_queue,
    parse_queue,
    render_queue,
)


def test_accepted_nominations_round_trip(tmp_path: Path) -> None:
    md = (
        "# Nominations\n\n"
        "## Stream A — Pre-traced\n\n"
        "- [ ] N-001 | api | sqli | src/x.ts:42 | rec: high | y/n: y\n"
        "    Summary: SQL injection.\n"
        "    Flows: F-1\n\n"
        "- [ ] N-002 | api | xss | src/y.ts:10 | rec: med | y/n: n\n"
        "    Summary: false positive.\n\n"
        "## Stream B — AI-discovered\n\n"
        "- [ ] N-003 | api | idor | src/z.ts:7 | rec: med | y/n: y\n"
        "    Summary: IDOR.\n"
    )
    items = accepted_nominations_to_queue(md)
    assert [i.nomination_id for i in items] == ["N-001", "N-003"]
    assert items[0].vector == "sqli"
    assert items[1].vector == "idor"


def test_render_then_parse(tmp_path: Path) -> None:
    items = [QueueItem(nomination_id="N-001", project="api", vector="sqli", loc="x.ts:42")]
    md = render_queue(items)
    parsed = parse_queue(md)
    assert parsed == items
```

### Step 2: Implementation

`ai_codescan/findings/queue.py`:

```python
"""Generate and parse findings_queue.md."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ai_codescan.gate import parse_nominations

_QUEUE_LINE = re.compile(
    r"^- \[(?P<state>[ x!])\] (?P<id>N-[\w-]+) \| (?P<project>[^|]+) \| "
    r"(?P<vector>[^|]+) \| (?P<loc>[^|]+)\s*$"
)


@dataclass(frozen=True, slots=True)
class QueueItem:
    nomination_id: str
    project: str
    vector: str
    loc: str


def accepted_nominations_to_queue(nominations_md: str) -> list[QueueItem]:
    """Filter nominations whose ``y/n:`` slot is ``y`` and project to ``QueueItem``s."""
    return [
        QueueItem(
            nomination_id=n.nomination_id,
            project=n.project,
            vector=n.vector,
            loc=n.loc,
        )
        for n in parse_nominations(nominations_md)
        if n.decision == "y"
    ]


def render_queue(items: list[QueueItem]) -> str:
    lines = ["# Findings queue", ""]
    for it in items:
        lines.append(f"- [ ] {it.nomination_id} | {it.project} | {it.vector} | {it.loc}")
    return "\n".join(lines) + "\n"


def parse_queue(md: str) -> list[QueueItem]:
    out: list[QueueItem] = []
    for line in md.splitlines():
        m = _QUEUE_LINE.match(line)
        if not m:
            continue
        out.append(
            QueueItem(
                nomination_id=m.group("id"),
                project=m.group("project").strip(),
                vector=m.group("vector").strip(),
                loc=m.group("loc").strip(),
            )
        )
    return out
```

### Step 3: Run + commit

```bash
uv run pytest tests/test_findings_queue.py -v
git add ai_codescan/findings/queue.py tests/test_findings_queue.py
git commit -m "feat(findings): findings_queue.md generator + parser"
```

Expected: 2 passed.

---

## Task 4: Deep-analyzer skill scaffold

**Files:**
- Create: `ai_codescan/skills/deep_analyzer/SKILL.md`
- Create: `ai_codescan/skills/deep_analyzer/prompts/analyzer.md`
- Create: `ai_codescan/skills/deep_analyzer/scripts/loop.sh`

### `SKILL.md`

```markdown
---
name: deep-analyzer
description: Per-finding deep analyser. Reads one slice at a time, walks evidence with symbol-on-demand tools, emits findings/<id>.md with status=unverified.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
license: apache-2.0
---

# Deep Analyser

For each item claimed from `findings_queue.md`:

1. Read the slice from `$AI_CODESCAN_SLICE_FILE` (JSON: source loc, sink class, ±5-line excerpts at each step).
2. Optionally walk the codebase further with Read / Grep / Glob over `$AI_CODESCAN_SOURCE_ROOT`.
3. Write `$AI_CODESCAN_FINDING_PATH` with frontmatter:
   ```
   ---
   finding_id: F-NNN
   nomination_id: N-NNN
   flow_id: F-X
   cwe: CWE-Y
   status: unverified
   title: "<one-line title>"
   ---

   <body: 6-section structure: Summary / Path / Evidence / Why-real / Mitigation / Open-questions>
   ```
4. Do not mutate other findings or the queue.
```

### `prompts/analyzer.md`

```markdown
# Deep analysis iteration

You analyse one taint flow at a time. Inputs:

- `$AI_CODESCAN_SLICE_FILE` — JSON describing one source/sink path with file/line excerpts.
- `$AI_CODESCAN_NOMINATION` — the nomination block from `nominations.md`.
- `$AI_CODESCAN_SOURCE_ROOT` — read-only snapshot tree.

Required output: write `$AI_CODESCAN_FINDING_PATH` exactly once, with valid frontmatter and a 6-section body:

1. **Summary** — 2-3 sentences in plain English.
2. **Path** — bullet list of (file:line: short paraphrase) for every step.
3. **Evidence** — fenced code blocks of the source-controlled sink and any sanitisers that should have fired but didn't.
4. **Why-real** — argue concretely why this is exploitable. If you suspect it's a false positive, say so and propose `status: rejected`.
5. **Mitigation** — concrete code change.
6. **Open questions** — what you'd want a human reviewer to verify.

Hard rules:
- Use ONLY data given. Do not fabricate file paths or line numbers.
- If the slice is too thin to be sure, output `status: unverified` and explain in Open questions.
- One finding file per iteration. Never edit other files.
```

### `scripts/loop.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
QUEUE="$RUN_DIR/findings_queue.md"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
PROMPT="$SKILL_DIR/prompts/analyzer.md"

[[ -f "$QUEUE" ]] || { echo "no $QUEUE" >&2; exit 1; }
mkdir -p "$RUN_DIR/findings" "$RUN_DIR/.done-analyze"

invoke_llm() {
  if [[ -n "$LLM_CMD" ]]; then "$LLM_CMD"; else
    local p; p="$(cat -)"; claude -p "$p"
  fi
}

while IFS= read -r line; do
  [[ "$line" =~ ^-\ \[\ \]\ (N-[A-Za-z0-9_-]+)\ \|\ ([^|]+)\ \|\ ([^|]+)\ \| ]] || continue
  nom_id="${BASH_REMATCH[1]}"
  done="$RUN_DIR/.done-analyze/${nom_id}"
  [[ -f "$done" ]] && continue
  finding_id="F-${nom_id#N-}"
  finding_path="$RUN_DIR/findings/${finding_id}.md"
  slice_file="$RUN_DIR/slices/${nom_id}.json"
  [[ -f "$slice_file" ]] || { echo "no slice for $nom_id (skipping)" >&2; continue; }

  AI_CODESCAN_SLICE_FILE="$slice_file" \
    AI_CODESCAN_NOMINATION="$line" \
    AI_CODESCAN_SOURCE_ROOT="$RUN_DIR/../source" \
    AI_CODESCAN_FINDING_PATH="$finding_path" \
    invoke_llm < "$PROMPT" || {
      echo "warning: $nom_id failed" >&2
      continue
    }
  touch "$done"
done < "$QUEUE"
```

```bash
chmod +x ai_codescan/skills/deep_analyzer/scripts/loop.sh
git add ai_codescan/skills/deep_analyzer/
git commit -m "feat(skill): deep_analyzer scaffold"
```

---

## Task 5: Python orchestrator (`analyzer.py`)

**Files:**
- Create: `ai_codescan/analyzer.py`
- Test: `tests/test_analyzer.py`

### Implementation

```python
"""Drive the deep_analyzer skill end-to-end."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path

import duckdb

from ai_codescan.findings.queue import (
    QueueItem,
    accepted_nominations_to_queue,
    render_queue,
)
from ai_codescan.llm import LLMConfig, is_available
from ai_codescan.nominator import write_llm_cmd_script
from ai_codescan.runs.state import RunState, save
from ai_codescan.slice import extract_slice

SKILL_DIR = Path(__file__).resolve().parent / "skills" / "deep_analyzer"


def _stage_slices(state: RunState, conn: duckdb.DuckDBPyConnection, items: list[QueueItem]) -> None:
    slices_dir = state.run_dir / "slices"
    slices_dir.mkdir(exist_ok=True)
    for it in items:
        # The flow id encoded in the queue's loc isn't authoritative; resolve via taxonomy.
        # Phase 2A heuristic: pick the first flow whose source matches the nomination's loc.
        flow_row = conn.execute(
            """
            SELECT f.fid FROM flows f
            JOIN taint_sources s ON s.tid = f.tid
            WHERE s.evidence_loc LIKE ? LIMIT 1
            """,
            [f"%{it.loc.split(':')[0]}%"],
        ).fetchone()
        if not flow_row:
            continue
        bundle = extract_slice(conn, flow_id=flow_row[0])
        if not bundle:
            continue
        (slices_dir / f"{it.nomination_id}.json").write_text(
            json.dumps(
                {
                    "flow_id": bundle.flow_id,
                    "cwe": bundle.cwe,
                    "source_loc": bundle.source_loc,
                    "sink_id": bundle.sink_id,
                    "steps": [asdict(step) for step in bundle.steps],
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def run_analyzer(
    state: RunState,
    *,
    repo_dir: Path,
    db_path: Path,
    llm: LLMConfig | None = None,
) -> Path:
    """Build the queue, stage slices, drive the deep-analyzer skill."""
    nominations = state.run_dir / "nominations.md"
    if not nominations.is_file():
        raise FileNotFoundError(f"no nominations.md at {nominations}")

    accepted = accepted_nominations_to_queue(nominations.read_text(encoding="utf-8"))
    queue_path = state.run_dir / "findings_queue.md"
    queue_path.write_text(render_queue(accepted), encoding="utf-8")

    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        _stage_slices(state, conn, accepted)
    finally:
        conn.close()

    state.phase = "analyze"
    save(state)

    effective = llm or LLMConfig(provider=state.llm_provider, model=state.llm_model)
    if not is_available(effective.provider):
        # No CLI on PATH — write empty findings dir so callers can proceed.
        (state.run_dir / "findings").mkdir(exist_ok=True)
        return queue_path

    cmd_script = write_llm_cmd_script(state.run_dir / ".llm-cmd-analyze.sh", effective)
    env = os.environ.copy()
    env["AI_CODESCAN_RUN_DIR"] = str(state.run_dir)
    env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
    env["AI_CODESCAN_LLM_CMD"] = str(cmd_script)

    subprocess.run(  # noqa: S603 - argv-only, no shell
        ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],  # noqa: S607
        env=env,
        check=True,
    )
    return queue_path
```

### Tests

```python
"""Tests for ai_codescan.analyzer (orchestrator surface)."""

from pathlib import Path

import duckdb

from ai_codescan.analyzer import run_analyzer
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.runs.state import load_or_create


def _seed(conn: duckdb.DuckDBPyConnection, file: str) -> None:
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [file])
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', NULL, 'http.body', 'name', ?)",
        [f"{file}:2"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', NULL, 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    steps = f'[["{file}", 2, 2], ["{file}", 5, 5]]'
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif', 'definite')",
        [steps],
    )


def test_run_analyzer_writes_queue_and_slices(
    tmp_path: Path, monkeypatch
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    src_dir = repo_dir / "source"
    src_dir.mkdir()
    src_file = src_dir / "x.ts"
    src_file.write_text("// 1\nconst id = req.body.name\n// 3\n// 4\nawait db.query(`x ${id}`)\n")

    db = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn, str(src_file))
    conn.close()

    state = load_or_create(repo_dir, engine="codeql", temperature=0.0, target_bug_classes=["sqli"])
    (state.run_dir / "nominations.md").write_text(
        "# Nominations\n\n## Stream A\n\n"
        "- [ ] N-001 | api | sqli | x.ts:2 | rec: high | y/n: y\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("PATH", "/nonexistent")
    queue_path = run_analyzer(state, repo_dir=repo_dir, db_path=db)
    assert queue_path.is_file()
    queue_text = queue_path.read_text(encoding="utf-8")
    assert "N-001" in queue_text
    slice_file = state.run_dir / "slices" / "N-001.json"
    assert slice_file.is_file()
```

```bash
uv run pytest tests/test_analyzer.py -v
git add ai_codescan/analyzer.py tests/test_analyzer.py
git commit -m "feat(analyzer): orchestrator stages slices + drives sub-agents"
```

Expected: 1 passed.

---

## Task 6: CLI `analyze` + `gate-2`

**Files:**
- Modify: `ai_codescan/cli.py`
- Modify: `tests/test_cli.py`

Add subcommands following the Phase 1 pattern. Reuse `_resolve_repo_id`, `_build_llm_config`. `analyze` invokes `run_analyzer`. `gate-2` opens the findings dir for human pruning (with `--yes` flipping all `unverified` to keep a default-accept stance, or `--reject-unverified` for the inverse).

```python
@app.command()
def analyze(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    llm_provider: Annotated[str, typer.Option("--llm-provider")] = "claude",
    llm_model: Annotated[str, typer.Option("--llm-model")] = "",
    temperature: Annotated[float, typer.Option("--temperature")] = 0.0,
) -> None:
    """Run the deep-analyzer skill against accepted nominations."""
    from ai_codescan.analyzer import run_analyzer

    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    repo_dir = cache_root / repo_id
    db_path = repo_dir / "index.duckdb"
    if not db_path.is_file():
        typer.echo("No index. Run prep first.", err=True)
        raise typer.Exit(code=1)
    runs_root = repo_dir / "runs"
    if not runs_root.is_dir() or not any(runs_root.iterdir()):
        typer.echo("No runs. Run nominate + gate-1 first.", err=True)
        raise typer.Exit(code=1)
    last_run = max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)
    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=temperature,
        target_bug_classes=[],
        run_id=last_run.name,
        llm_provider=llm_provider,
        llm_model=llm_model or None,
    )
    llm = _build_llm_config(llm_provider, llm_model)
    queue = run_analyzer(state, repo_dir=repo_dir, db_path=db_path, llm=llm)
    typer.echo(f"queue at {queue}")


@app.command("gate-2")
def gate_2(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    yes: Annotated[bool, typer.Option("--yes")] = False,
) -> None:
    """Open findings/ for HITL pruning, or --yes to keep all 'unverified' as-is."""
    cache_root: Path = ctx.obj["cache_root"]
    repo_id = _resolve_repo_id(cache_root, repo_id)
    runs_root = cache_root / repo_id / "runs"
    last_run = max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)
    findings_dir = last_run / "findings"
    if not findings_dir.is_dir():
        typer.echo("No findings dir. Run analyze first.", err=True)
        raise typer.Exit(code=1)
    if yes:
        typer.echo(f"keeping all findings under {findings_dir} as-is")
        return
    editor = os.environ.get("EDITOR", "vi")
    subprocess.run(  # noqa: S603 - editor is user-controlled, no shell
        [editor, str(findings_dir)],  # noqa: S607
        check=False,
    )
```

Tests append to `tests/test_cli.py` covering `analyze --help` and `gate-2 --yes` against a seeded findings dir.

```bash
git add ai_codescan/cli.py tests/test_cli.py
git commit -m "feat(cli): analyze + gate-2 subcommands"
```

---

## Task 7: Smoke test + tag phase-2a

```bash
make check
uv run ai-codescan run /tmp/tmp-express --target-bug-class injection --yes
uv run ai-codescan analyze
uv run ai-codescan gate-2 --yes
ls ~/.ai_codescan/repos/tmp-express-*/runs/*/findings/

git tag -a phase-2a -m "Phase 2A: deep analyser + gate 2"
```

---

## Self-review

- §4.1 deep analyser → Tasks 1, 4, 5
- §6 `analyze`, `gate-2` CLI → Task 6
- Findings frontmatter format → Task 2
- findings_queue.md atomic-line claim → Task 3 + skill loop.sh
- LLM provider passthrough (claude/gemini/codex) → Task 5 reuses `write_llm_cmd_script`

Deferred to 2B–2E: validator (sandbox), report templating, Layer 5 storage taint, `--engine llm-heavy`.
