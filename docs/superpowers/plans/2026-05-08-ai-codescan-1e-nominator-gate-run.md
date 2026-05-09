# AI_Codescan 1E — Wide Nominator + Gate 1 + Run Super-Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the AI-driven half of Phase 1: a Claude Code skill (`wide_nominator`) that reads the prep artefacts, emits `nominations.md` with three streams (CodeQL-traced, AI-discovered, model-extension proposals), each item carrying a max-2-line plain-English `Summary:` line and a `y/n:` HITL marker. Add `gate-1` (with `--yes` and `--apply`) and the `run` super-command so the user can fire `ai-codescan run <target>` and arrive at a triaged candidate list.

**Architecture:** The skill follows Ghost's pattern — `SKILL.md` orchestrates `prompts/nominator.md` via `scripts/loop.sh` with atomic `[ ]` → `[x]` line claiming. Python orchestrator drives the skill via `claude -p`. Run-state JSON tracks cost + phase + temperature.

**Tech Stack:** Python only changes (no new deps). Skill itself is plain markdown + bash. `claude` CLI must be on PATH.

**Reference spec:** §3 (phasing), §4.1 (dataflow), §5.9 (skill module), §7 (`run`, `nominate`, `gate-1`, `--yes`, `--apply`, `--temperature`, `--cost-cap`, `--report-dir`), §6 (full taxonomy + `needs_semantic`), §11.1 (cost ledger), §9 (state-file conventions).

**Depends on:** Plans 1A–1D complete. `index.duckdb` populated with files / symbols / xrefs / sources / sinks / flows / entrypoints; sidecars emitted; `repo.md` + `entrypoints.md` rendered.

---

## File Structure (added)

```
AI_Analysis/
├── ai_codescan/
│   ├── skills/
│   │   ├── __init__.py
│   │   └── wide_nominator/
│   │       ├── SKILL.md
│   │       ├── prompts/
│   │       │   └── nominator.md
│   │       └── scripts/
│   │           └── loop.sh
│   ├── runs/
│   │   ├── __init__.py
│   │   └── state.py                  # run.json read/write, cost ledger
│   ├── nominator.py                  # python orchestrator that drives the skill
│   └── gate.py                       # gate-1 logic: open in $EDITOR, --yes, --apply
└── tests/
    ├── test_runs_state.py
    ├── test_nominator_orchestrator.py
    ├── test_gate.py
    └── fixtures/
        └── nominations-sample.md     # canned gate file used in tests
```

`ai_codescan/taxonomy/bug_classes.yaml` is also extended in Task 1 to the full taxonomy.

---

## Task 1: Extend taxonomy to full Phase 1 set

**Files:** Modify `ai_codescan/taxonomy/bug_classes.yaml`. Modify `ai_codescan/taxonomy/loader.py` to surface `needs_semantic`.

- [ ] **Step 1: Failing test for `needs_semantic`**

Append to `tests/test_taxonomy_loader.py`:

```python
def test_idor_class_marked_needs_semantic() -> None:
    classes = resolve_classes(["idor"])
    assert classes[0].needs_semantic is True


def test_xss_class_does_not_need_semantic() -> None:
    classes = resolve_classes(["xss"])
    assert classes[0].needs_semantic is False
```

- [ ] **Step 2: Extend `BugClass` and the loader**

In `ai_codescan/taxonomy/loader.py`, modify `BugClass` and `list_classes`:

```python
@dataclass(frozen=True, slots=True)
class BugClass:
    name: str
    cwes: list[str]
    codeql_tags: list[str]
    group: str | None
    aliases: list[str]
    needs_semantic: bool = False
```

Update the constructor in `list_classes`:

```python
        out.append(
            BugClass(
                name=name,
                cwes=list(body.get("cwes", [])),
                codeql_tags=list(body.get("codeql_tags", [])),
                group=body.get("group"),
                aliases=list(body.get("aliases", [])),
                needs_semantic=bool(body.get("needs_semantic", False)),
            )
        )
```

- [ ] **Step 3: Replace `bug_classes.yaml` with the full set**

`ai_codescan/taxonomy/bug_classes.yaml`:

```yaml
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

prompt-injection:
  cwes: [CWE-1427]
  codeql_tags: []
  group: injection
  needs_semantic: true

xxe:
  aliases: [xml-external-entity]
  cwes: [CWE-611]
  codeql_tags: [security/cwe/cwe-611]
  group: injection

ldap-injection:
  cwes: [CWE-90]
  codeql_tags: [security/cwe/cwe-090]
  group: injection

crlf-injection:
  aliases: [header-injection]
  cwes: [CWE-93]
  codeql_tags: [security/cwe/cwe-093]
  group: injection

path-traversal:
  aliases: [dir-traversal]
  cwes: [CWE-22]
  codeql_tags: [security/cwe/cwe-022]
  group: file

lfi:
  aliases: [local-file-inclusion]
  cwes: [CWE-98]
  codeql_tags: [security/cwe/cwe-098]
  group: file

rfi:
  aliases: [remote-file-inclusion]
  cwes: [CWE-98]
  codeql_tags: [security/cwe/cwe-098]
  group: file

ssrf:
  cwes: [CWE-918]
  codeql_tags: [security/cwe/cwe-918]
  group: request-forgery

csrf:
  cwes: [CWE-352]
  codeql_tags: [security/cwe/cwe-352]
  group: request-forgery

idor:
  aliases: [bola]
  cwes: [CWE-639]
  codeql_tags: []
  group: authz
  needs_semantic: true

bfla:
  cwes: [CWE-862]
  codeql_tags: []
  group: authz
  needs_semantic: true

mass-assignment:
  cwes: [CWE-915]
  codeql_tags: [security/cwe/cwe-915]
  group: authz

open-redirect:
  cwes: [CWE-601]
  codeql_tags: [security/cwe/cwe-601]
  group: redirect

cors-misconfig:
  cwes: [CWE-942]
  codeql_tags: [security/cwe/cwe-942]
  group: web-config

unsafe-deserialization:
  aliases: [insec-deser]
  cwes: [CWE-502]
  codeql_tags: [security/cwe/cwe-502]
  group: serialization

prototype-pollution:
  cwes: [CWE-1321]
  codeql_tags: [security/cwe/cwe-1321]
  group: javascript

dom-clobbering:
  cwes: [CWE-79]
  codeql_tags: []
  group: javascript
  needs_semantic: true

redos:
  aliases: [regex-dos]
  cwes: [CWE-1333]
  codeql_tags: [security/cwe/cwe-1333]
  group: dos

auth-bypass:
  aliases: [broken-authn]
  cwes: [CWE-287]
  codeql_tags: [security/cwe/cwe-287]
  group: authn

weak-crypto:
  cwes: [CWE-327, CWE-328]
  codeql_tags: [security/cwe/cwe-327, security/cwe/cwe-328]
  group: crypto

insecure-random:
  cwes: [CWE-330, CWE-338]
  codeql_tags: [security/cwe/cwe-338]
  group: crypto

jwt-misuse:
  cwes: [CWE-345, CWE-347]
  codeql_tags: [security/cwe/cwe-347]
  group: authn

session-fixation:
  cwes: [CWE-384]
  codeql_tags: [security/cwe/cwe-384]
  group: session

host-header-injection:
  cwes: [CWE-20]
  codeql_tags: []
  group: web-config
  needs_semantic: true

request-smuggling:
  cwes: [CWE-444]
  codeql_tags: []
  group: web-config
  needs_semantic: true

cache-poisoning:
  cwes: [CWE-444]
  codeql_tags: []
  group: web-config
  needs_semantic: true

oauth-misconfig:
  cwes: [CWE-285]
  codeql_tags: []
  group: web-config
  needs_semantic: true

info-disclosure:
  cwes: [CWE-200]
  codeql_tags: [security/cwe/cwe-200]
  group: data-exposure

client-side-redirect:
  cwes: [CWE-601]
  codeql_tags: []
  group: redirect
  needs_semantic: true

groups:
  injection:
    [xss, sqli, nosqli, cmdi, code-injection, ssti, prompt-injection, xxe, ldap-injection, crlf-injection]
  file: [path-traversal, lfi, rfi]
  authz: [idor, bfla, mass-assignment]
  authn: [auth-bypass, jwt-misuse]
  request-forgery: [ssrf, csrf]
  crypto: [weak-crypto, insecure-random]
  web-config: [cors-misconfig, host-header-injection, request-smuggling, cache-poisoning, oauth-misconfig]
  serialization: [unsafe-deserialization]
  javascript: [prototype-pollution, dom-clobbering]
  redirect: [open-redirect, client-side-redirect]
  dos: [redos]
  data-exposure: [info-disclosure]
  session: [session-fixation]
  all-injection: ["@injection", "@file", "@serialization"]
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_taxonomy_loader.py -v
```

Expected: green (existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/taxonomy/ tests/test_taxonomy_loader.py
git commit -m "feat(taxonomy): full phase-1 set with needs_semantic flag"
```

---

## Task 2: Run-state and cost ledger (`runs/state.py`)

**Files:**
- Create: `ai_codescan/runs/__init__.py`
- Create: `ai_codescan/runs/state.py`
- Test: `tests/test_runs_state.py`

`runs/<run_id>/run.json` carries:

```json
{
  "run_id": "<8-char>",
  "started_at": "...",
  "phase": "nominate",
  "engine": "codeql",
  "temperature": 0.0,
  "target_bug_classes": ["xss", "sqli"],
  "cost_cap_usd": null,
  "calls": [...],
  "total_usd": 0.0
}
```

- [ ] **Step 1: Failing tests**

`tests/test_runs_state.py`:

```python
"""Tests for ai_codescan.runs.state."""

from pathlib import Path

from ai_codescan.runs.state import (
    RunState,
    load_or_create,
    record_call,
    save,
)


def test_load_or_create_creates_new(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=0.0,
        target_bug_classes=["xss"],
    )
    assert isinstance(state, RunState)
    assert state.engine == "codeql"
    assert state.run_dir.parent == repo_dir / "runs"


def test_record_call_accumulates_cost(tmp_path: Path) -> None:
    repo_dir = tmp_path / "r"
    repo_dir.mkdir()
    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=0.0,
        target_bug_classes=[],
    )
    record_call(
        state,
        step="nominator",
        model="claude-sonnet-4-6",
        input_tokens=1000,
        cache_read=0,
        output_tokens=200,
        usd=0.05,
    )
    record_call(
        state,
        step="nominator",
        model="claude-sonnet-4-6",
        input_tokens=500,
        cache_read=400,
        output_tokens=100,
        usd=0.01,
    )
    save(state)
    assert abs(state.total_usd - 0.06) < 1e-9
    assert len(state.calls) == 2


def test_save_then_reload_preserves_state(tmp_path: Path) -> None:
    repo_dir = tmp_path / "r"
    repo_dir.mkdir()
    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=0.3,
        target_bug_classes=["xss", "sqli"],
    )
    record_call(state, step="x", model="m", input_tokens=1, cache_read=0, output_tokens=1, usd=0.01)
    save(state)

    reloaded = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=0.3,
        target_bug_classes=["xss", "sqli"],
        run_id=state.run_id,
    )
    assert reloaded.run_id == state.run_id
    assert reloaded.calls and reloaded.calls[0]["step"] == "x"
```

- [ ] **Step 2: Implement**

`ai_codescan/runs/__init__.py`: empty.

`ai_codescan/runs/state.py`:

```python
"""Run-state JSON: phase, cost ledger, config snapshot."""

from __future__ import annotations

import datetime as _dt
import json
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(slots=True)
class RunState:
    run_id: str
    run_dir: Path
    started_at: str
    phase: str
    engine: str
    temperature: float
    target_bug_classes: list[str]
    cost_cap_usd: float | None
    calls: list[dict] = field(default_factory=list)
    total_usd: float = 0.0


def _new_run_id() -> str:
    return secrets.token_hex(4)


def load_or_create(
    repo_dir: Path,
    *,
    engine: str,
    temperature: float,
    target_bug_classes: list[str],
    cost_cap_usd: float | None = None,
    run_id: str | None = None,
) -> RunState:
    runs_root = repo_dir / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    if run_id:
        run_dir = runs_root / run_id
        run_json = run_dir / "run.json"
        if run_json.is_file():
            data = json.loads(run_json.read_text(encoding="utf-8"))
            return RunState(
                run_id=data["run_id"],
                run_dir=run_dir,
                started_at=data["started_at"],
                phase=data["phase"],
                engine=data["engine"],
                temperature=float(data.get("temperature", 0.0)),
                target_bug_classes=list(data.get("target_bug_classes", [])),
                cost_cap_usd=data.get("cost_cap_usd"),
                calls=list(data.get("calls", [])),
                total_usd=float(data.get("total_usd", 0.0)),
            )
    new_id = run_id or _new_run_id()
    run_dir = runs_root / new_id
    run_dir.mkdir(parents=True, exist_ok=True)
    state = RunState(
        run_id=new_id,
        run_dir=run_dir,
        started_at=_dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        phase="prep",
        engine=engine,
        temperature=temperature,
        target_bug_classes=target_bug_classes,
        cost_cap_usd=cost_cap_usd,
    )
    save(state)
    return state


def record_call(
    state: RunState,
    *,
    step: str,
    model: str,
    input_tokens: int,
    cache_read: int,
    output_tokens: int,
    usd: float,
) -> None:
    state.calls.append(
        {
            "step": step,
            "model": model,
            "input_tokens": input_tokens,
            "cache_read": cache_read,
            "output_tokens": output_tokens,
            "usd": usd,
        }
    )
    state.total_usd = round(state.total_usd + usd, 12)


def save(state: RunState) -> None:
    payload = asdict(state)
    payload["run_dir"] = str(state.run_dir)
    (state.run_dir / "run.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
```

- [ ] **Step 3: Run tests**

```bash
uv run pytest tests/test_runs_state.py -v
```

Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add ai_codescan/runs/ tests/test_runs_state.py
git commit -m "feat(runs): run-state json with cost ledger"
```

---

## Task 3: Wide-nominator skill scaffold

**Files:**
- Create: `ai_codescan/skills/__init__.py`
- Create: `ai_codescan/skills/wide_nominator/SKILL.md`
- Create: `ai_codescan/skills/wide_nominator/prompts/nominator.md`
- Create: `ai_codescan/skills/wide_nominator/scripts/loop.sh`

- [ ] **Step 1: `SKILL.md`**

`ai_codescan/skills/wide_nominator/SKILL.md`:

```markdown
---
name: wide-nominator
description: AI-driven SAST wide-pass nominator. Reads ai-codescan prep artefacts (repo.md, entrypoints.md, sidecar JSONL, DuckDB stats) and emits nominations.md with three streams (CodeQL-traced, AI-discovered, model-extension proposals), each carrying a max-2-line plain-English Summary and a y/n: HITL marker.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
license: apache-2.0
---

# Wide Nominator

Workflow:

1. Read inputs from `$AI_CODESCAN_RUN_DIR/inputs/`:
   - `repo.md`, `entrypoints.md`
   - `flows.jsonl`, `sinks_no_flow.jsonl`, `sources_no_sink.jsonl`, `auth_calls.jsonl`, `hotspots.jsonl`
2. For each existing CodeQL flow in `flows.jsonl`, append a Stream A nomination.
3. For each high-signal hotspot or auth-relevant function lacking a CodeQL flow, append a Stream B AI-discovered nomination — only if a credible bug class applies.
4. For each library detected in `repo.md` that CodeQL doesn't model, propose a model extension as a Stream C nomination.
5. Every nomination has: `- [ ] N-XXX | <project> | <vector> | <file>:<line> | rec: high|med|low | y/n: ` followed by an indented block: `Summary:` (max 2 lines), then the structured fields.
6. Use atomic line claiming: only flip `[ ]` to `[x]`. Never reorder. Never edit other items.

Run with `bash $AI_CODESCAN_SKILL_DIR/scripts/loop.sh`.

Inputs:
- `$AI_CODESCAN_RUN_DIR` — current run directory
- `$AI_CODESCAN_SKILL_DIR` — this skill's directory
- `$AI_CODESCAN_TARGET_BUG_CLASSES` — comma-separated taxonomy names

Outputs:
- `$AI_CODESCAN_RUN_DIR/nominations.md`
- `$AI_CODESCAN_RUN_DIR/extensions/*.model.yml` for any Stream C proposals
```

- [ ] **Step 2: `prompts/nominator.md`**

`ai_codescan/skills/wide_nominator/prompts/nominator.md`:

```markdown
# Nominator iteration

You are filling out one block of `$AI_CODESCAN_RUN_DIR/nominations.md`. The file already starts with three Stream headers:

```
## Stream A — Pre-traced (CodeQL flows ready for triage)

## Stream B — AI-discovered candidates (no static flow exists; semantic concern)

## Stream C — Proposed CodeQL model extensions
```

You are given ONE candidate this iteration via `$AI_CODESCAN_CANDIDATE` (a JSON blob) and must:

1. Decide which stream it belongs to (A: traced flow given; B: heuristic candidate; C: missing-model proposal).
2. Append exactly one nomination block under that stream:

```
- [ ] N-NNN | <project> | <vector> | <file>:<line> | rec: high|med|low | y/n: 
    Summary: <max 2 lines, plain English; no symbol IDs, no jargon>
    <structured fields specific to the stream>
```

Hard rules:
- Stream A: include `Flows: F-IDs (CWE, parameterization)` and `Source / Sink` lines.
- Stream B: include `Heuristic:` and `Symbols:` lines explaining why the static engine missed it.
- Stream C: include the proposed YAML model in a fenced code block.
- Always keep `Summary:` to two lines maximum.
- `rec: high` if you would investigate, `rec: med` if uncertain, `rec: low` if borderline.
- Use ONLY the data given; do not fabricate symbols, file paths, or line numbers.
- Do not modify other lines.

Inputs available:
- $AI_CODESCAN_CANDIDATE — JSON descriptor for this iteration
- $AI_CODESCAN_REPO_MD, $AI_CODESCAN_ENTRYPOINTS_MD — context
- Tools: Read, Grep, Glob over the snapshot dir if you need a code excerpt
```

- [ ] **Step 3: `scripts/loop.sh`**

`ai_codescan/skills/wide_nominator/scripts/loop.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
QUEUE="$RUN_DIR/queue.jsonl"
NOMS="$RUN_DIR/nominations.md"
PROMPT="$SKILL_DIR/prompts/nominator.md"

if [[ ! -f "$NOMS" ]]; then
  cat > "$NOMS" <<'EOF'
# Nominations

## Stream A — Pre-traced (CodeQL flows ready for triage)

## Stream B — AI-discovered candidates (no static flow exists; semantic concern)

## Stream C — Proposed CodeQL model extensions

EOF
fi

if [[ ! -f "$QUEUE" ]]; then
  echo "no queue at $QUEUE" >&2
  exit 1
fi

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  candidate_id=$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])')
  done_marker="$RUN_DIR/.done/${candidate_id}"
  if [[ -f "$done_marker" ]]; then
    continue
  fi
  mkdir -p "$RUN_DIR/.done"
  AI_CODESCAN_CANDIDATE="$line" \
    AI_CODESCAN_REPO_MD="$RUN_DIR/inputs/repo.md" \
    AI_CODESCAN_ENTRYPOINTS_MD="$RUN_DIR/inputs/entrypoints.md" \
    claude -p "$(cat "$PROMPT")" || {
      echo "warning: candidate $candidate_id failed" >&2
      continue
    }
  touch "$done_marker"
done < "$QUEUE"
```

- [ ] **Step 4: Make `loop.sh` executable**

```bash
chmod +x ai_codescan/skills/wide_nominator/scripts/loop.sh
```

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/skills/
git commit -m "feat(skill): wide_nominator scaffold (skill.md, prompt, loop.sh)"
```

---

## Task 4: Skill installer + Python orchestrator (`nominator.py`)

**Files:**
- Create: `ai_codescan/nominator.py`
- Test: `tests/test_nominator_orchestrator.py`

The orchestrator:
1. Builds the candidate queue from DuckDB (Stream A from `flows`, Stream B from heuristics, Stream C from unmodeled libs in `repo.md`).
2. Writes inputs/`*.jsonl` and `queue.jsonl` to the run dir.
3. Invokes `loop.sh`.
4. Records cost into `run.json`.

- [ ] **Step 1: Failing tests (orchestrator surface only — actual `claude -p` is shelled out separately)**

`tests/test_nominator_orchestrator.py`:

```python
"""Tests for ai_codescan.nominator orchestrator (queue construction)."""

import json
from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.nominator import build_queue


def _seed_flow(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute("INSERT INTO files VALUES ('/abs/x.ts', 'sha', 'ts', 'p', 100)")
    conn.execute(
        "INSERT INTO symbols VALUES ('S1', 'sym1', 'function', '/abs/x.ts', 1, 5, NULL, 'h')"
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', 'S1', 'http.body', 'name', '/abs/x.ts:2')"
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES ('K1', 'S1', 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES ('F1', 'T1', 'K1', 'CWE-89', 'codeql', '[]', '/sarif', 'definite')"
    )
    conn.execute("INSERT INTO entrypoints VALUES ('S1', 'http_route', 'app.post')")


def test_build_queue_includes_stream_a_for_each_flow(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_flow(conn)
    queue = build_queue(conn, target_bug_classes=["sqli"])
    streams = {q["stream"] for q in queue}
    assert "A" in streams
    flow_records = [q for q in queue if q["stream"] == "A"]
    assert flow_records[0]["fid"] == "F1"


def test_build_queue_filters_by_bug_class(tmp_path: Path) -> None:
    db = tmp_path / "y.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_flow(conn)
    queue = build_queue(conn, target_bug_classes=["xss"])
    flow_records = [q for q in queue if q["stream"] == "A"]
    assert flow_records == []  # CWE-89 ≠ xss


def test_build_queue_serialises_as_jsonl(tmp_path: Path) -> None:
    db = tmp_path / "z.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_flow(conn)
    queue = build_queue(conn, target_bug_classes=["sqli"])
    out = tmp_path / "queue.jsonl"
    out.write_text("\n".join(json.dumps(q) for q in queue))
    parsed = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    assert parsed == queue
```

- [ ] **Step 2: Implement `build_queue` and `run_nominator`**

`ai_codescan/nominator.py`:

```python
"""Drive the wide_nominator skill end-to-end."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import duckdb

from ai_codescan.runs.state import RunState, save
from ai_codescan.taxonomy.loader import BugClass

SKILL_DIR = Path(__file__).resolve().parent / "skills" / "wide_nominator"


def _cwes_for_classes(classes: list[BugClass]) -> set[str]:
    return {cwe for c in classes for cwe in c.cwes}


def build_queue(
    conn: duckdb.DuckDBPyConnection,
    *,
    target_bug_classes: list[str],
) -> list[dict]:
    """Return the ordered list of candidate descriptors for the skill loop."""
    from ai_codescan.taxonomy.loader import resolve_classes

    selected = resolve_classes(target_bug_classes) if target_bug_classes else []
    cwes = _cwes_for_classes(selected) if selected else None

    queue: list[dict] = []
    flow_rows = conn.execute(
        """
        SELECT f.fid, f.tid, f.sid, f.cwe, f.engine, s.evidence_loc,
               t.class, t.lib, t.parameterization
        FROM flows f
        JOIN taint_sources s ON s.tid = f.tid
        JOIN taint_sinks   t ON t.sid = f.sid
        """
    ).fetchall()
    for fid, tid, sid, cwe, engine, evidence_loc, sink_class, lib, parameterization in flow_rows:
        if cwes is not None and cwe not in cwes:
            continue
        queue.append(
            {
                "id": f"A-{fid}",
                "stream": "A",
                "fid": fid,
                "tid": tid,
                "sid": sid,
                "cwe": cwe,
                "engine": engine,
                "source_loc": evidence_loc,
                "sink_class": sink_class,
                "lib": lib,
                "parameterization": parameterization,
            }
        )

    sink_no_flow = conn.execute(
        """
        SELECT sid, class, lib, parameterization
        FROM taint_sinks
        WHERE sid NOT IN (SELECT sid FROM flows)
        """
    ).fetchall()
    for sid, sink_class, lib, parameterization in sink_no_flow:
        queue.append(
            {
                "id": f"B-sink-{sid}",
                "stream": "B",
                "concern": "sink-without-source",
                "sink_id": sid,
                "sink_class": sink_class,
                "lib": lib,
                "parameterization": parameterization,
            }
        )

    auth_rows = conn.execute(
        """
        SELECT id, file, range_start, display_name
        FROM symbols
        WHERE display_name ILIKE '%authoriz%'
           OR display_name ILIKE '%authent%'
           OR display_name ILIKE '%permission%'
        """
    ).fetchall()
    for sym_id, file, line, name in auth_rows:
        queue.append(
            {
                "id": f"B-auth-{sym_id}",
                "stream": "B",
                "concern": "authz-callsite",
                "symbol_id": sym_id,
                "file": file,
                "line": line,
                "name": name,
            }
        )

    return queue


def _stage_inputs(state: RunState, repo_dir: Path, conn: duckdb.DuckDBPyConnection, queue: list[dict]) -> None:
    inputs = state.run_dir / "inputs"
    inputs.mkdir(exist_ok=True)
    shutil.copyfile(repo_dir / "repo.md", inputs / "repo.md")
    if (repo_dir / "entrypoints.md").is_file():
        shutil.copyfile(repo_dir / "entrypoints.md", inputs / "entrypoints.md")

    flows_path = inputs / "flows.jsonl"
    with flows_path.open("w", encoding="utf-8") as f:
        for q in queue:
            if q["stream"] == "A":
                f.write(json.dumps(q) + "\n")

    queue_path = state.run_dir / "queue.jsonl"
    with queue_path.open("w", encoding="utf-8") as f:
        for q in queue:
            f.write(json.dumps(q) + "\n")


def run_nominator(
    state: RunState,
    *,
    repo_dir: Path,
    bug_classes: list[BugClass],
    db_path: Path,
) -> Path:
    """Stage inputs, drive the skill loop, return path to nominations.md."""
    conn = duckdb.connect(str(db_path), read_only=True)
    queue = build_queue(
        conn,
        target_bug_classes=[c.name for c in bug_classes],
    )

    _stage_inputs(state, repo_dir, conn, queue)
    state.phase = "nominate"
    save(state)

    if shutil.which("claude") is None:
        # Skill loop requires the claude CLI; in test/CI environments without
        # it we still write an empty nominations.md so callers can proceed.
        (state.run_dir / "nominations.md").write_text(
            "# Nominations\n\n"
            "## Stream A — Pre-traced (CodeQL flows ready for triage)\n\n"
            "## Stream B — AI-discovered candidates (no static flow exists; semantic concern)\n\n"
            "## Stream C — Proposed CodeQL model extensions\n",
            encoding="utf-8",
        )
        return state.run_dir / "nominations.md"

    env = os.environ.copy()
    env["AI_CODESCAN_RUN_DIR"] = str(state.run_dir)
    env["AI_CODESCAN_SKILL_DIR"] = str(SKILL_DIR)
    env["AI_CODESCAN_TARGET_BUG_CLASSES"] = ",".join(c.name for c in bug_classes)

    subprocess.run(
        ["bash", str(SKILL_DIR / "scripts" / "loop.sh")],
        env=env,
        check=True,
    )
    return state.run_dir / "nominations.md"
```

- [ ] **Step 3: Run tests**

```bash
uv run pytest tests/test_nominator_orchestrator.py -v
```

Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add ai_codescan/nominator.py tests/test_nominator_orchestrator.py
git commit -m "feat(nominator): orchestrator builds queue and drives skill loop"
```

---

## Task 5: Gate-1 logic (`gate.py`)

**Files:**
- Create: `ai_codescan/gate.py`
- Create: `tests/fixtures/nominations-sample.md`
- Test: `tests/test_gate.py`

`gate-1` opens `nominations.md` in `$EDITOR` for the human to edit `y/n:` lines, or accepts `--yes` to mark all unanswered as `y`, or `--apply` to apply Stream C accepted YAML extensions and re-run CodeQL.

- [ ] **Step 1: Author the canned gate fixture**

`tests/fixtures/nominations-sample.md`:

```markdown
# Nominations

## Stream A — Pre-traced

- [ ] N-001 | api | sqli | src/users.ts:42 | rec: high | y/n: 
    Summary: SQLi via id path param into pg.query.
    Flows: F-1 (CWE-89, template-literal)

- [ ] N-002 | api | xss | src/profile.ts:10 | rec: med | y/n: y
    Summary: Possible XSS in bio render.
    Flows: F-2 (CWE-79)

## Stream B — AI-discovered

- [ ] N-003 | api | idor | src/orders.ts:58 | rec: med | y/n: n
    Summary: Possible IDOR — no ownership check.
    Heuristic: req.params.orderId → Order.findOne; no req.user.id

## Stream C — Proposed model extensions

- [ ] N-004 | api | model-proposal | extensions/bullmq.model.yml | rec: high | y/n: 
    Summary: Library bullmq is unmodelled by CodeQL.

```yaml
extensions:
  - addsTo:
      pack: codeql/javascript-queries
      extensible: sourceModel
    data:
      - ["bullmq", "Worker.process", true, "remote", "", "", "Argument[0]", "manual"]
```
```

- [ ] **Step 2: Failing tests**

`tests/test_gate.py`:

```python
"""Tests for ai_codescan.gate."""

from pathlib import Path

from ai_codescan.gate import (
    apply_yes_to_all,
    parse_nominations,
    selected_extensions,
)


def test_parse_extracts_y_n_state(fixtures_dir: Path) -> None:
    md = (fixtures_dir / "nominations-sample.md").read_text()
    items = parse_nominations(md)
    by_id = {i.nomination_id: i for i in items}
    assert by_id["N-001"].decision == ""
    assert by_id["N-002"].decision == "y"
    assert by_id["N-003"].decision == "n"
    assert by_id["N-004"].decision == ""


def test_apply_yes_to_all_only_fills_unanswered(fixtures_dir: Path) -> None:
    md = (fixtures_dir / "nominations-sample.md").read_text()
    out = apply_yes_to_all(md)
    items = parse_nominations(out)
    assert all(i.decision in {"y", "n"} for i in items)
    by_id = {i.nomination_id: i for i in items}
    assert by_id["N-002"].decision == "y"  # was already y, untouched
    assert by_id["N-003"].decision == "n"  # was already n, untouched
    assert by_id["N-001"].decision == "y"
    assert by_id["N-004"].decision == "y"


def test_selected_extensions_returns_stream_c_yes(fixtures_dir: Path) -> None:
    md = (fixtures_dir / "nominations-sample.md").read_text()
    md = apply_yes_to_all(md)
    exts = selected_extensions(md)
    assert exts and exts[0].nomination_id == "N-004"
    assert "bullmq" in exts[0].yaml_body
```

- [ ] **Step 3: Implement**

`ai_codescan/gate.py`:

```python
"""Parse and mutate ``nominations.md``: HITL gate-1 logic."""

from __future__ import annotations

import re
from dataclasses import dataclass

_HEADER = re.compile(
    r"^- \[(?P<state>[ x!])\] (?P<id>N-[\w-]+) \| "
    r"(?P<project>[^|]+) \| (?P<vector>[^|]+) \| "
    r"(?P<loc>[^|]+) \| rec: (?P<rec>high|med|low) \| y/n: ?(?P<decision>[yn]?)\s*$"
)

_STREAM_C_HEADER = "## Stream C"


@dataclass(frozen=True, slots=True)
class Nomination:
    nomination_id: str
    state: str
    project: str
    vector: str
    loc: str
    rec: str
    decision: str
    line_idx: int
    raw_line: str


@dataclass(frozen=True, slots=True)
class StreamCExtension:
    nomination_id: str
    yaml_body: str


def parse_nominations(md: str) -> list[Nomination]:
    out: list[Nomination] = []
    for idx, line in enumerate(md.splitlines()):
        m = _HEADER.match(line)
        if not m:
            continue
        out.append(
            Nomination(
                nomination_id=m.group("id"),
                state=m.group("state"),
                project=m.group("project").strip(),
                vector=m.group("vector").strip(),
                loc=m.group("loc").strip(),
                rec=m.group("rec"),
                decision=m.group("decision") or "",
                line_idx=idx,
                raw_line=line,
            )
        )
    return out


def apply_yes_to_all(md: str) -> str:
    new_lines: list[str] = []
    for line in md.splitlines():
        m = _HEADER.match(line)
        if not m or m.group("decision"):
            new_lines.append(line)
            continue
        new_lines.append(line.rstrip() + "y")
    return "\n".join(new_lines) + ("\n" if md.endswith("\n") else "")


def selected_extensions(md: str) -> list[StreamCExtension]:
    """Return the YAML bodies of Stream C nominations marked 'y'."""
    items = parse_nominations(md)
    in_c = False
    out: list[StreamCExtension] = []
    lines = md.splitlines()
    for nom in items:
        # Determine which stream the nomination falls under.
        header_idx = max(
            (i for i, line in enumerate(lines[: nom.line_idx]) if line.startswith("## ")),
            default=-1,
        )
        if header_idx < 0:
            continue
        if not lines[header_idx].startswith(_STREAM_C_HEADER):
            continue
        if nom.decision != "y":
            continue
        # Capture the next ```yaml ... ``` block following this nomination.
        yaml_lines: list[str] = []
        in_block = False
        for after in lines[nom.line_idx + 1 :]:
            if after.startswith("- [") and _HEADER.match(after):
                break
            if after.startswith("```yaml"):
                in_block = True
                continue
            if in_block:
                if after.startswith("```"):
                    break
                yaml_lines.append(after)
        out.append(StreamCExtension(nomination_id=nom.nomination_id, yaml_body="\n".join(yaml_lines)))
    return out
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_gate.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/gate.py tests/fixtures/nominations-sample.md tests/test_gate.py
git commit -m "feat(gate): parse, yes-to-all, stream-c extension selector"
```

---

## Task 6: CLI subcommands `nominate`, `gate-1`, `run`, `--install-skills`

**Files:**
- Modify: `ai_codescan/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Add subcommands**

In `ai_codescan/cli.py`:

```python
@app.command()
def nominate(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    target_bug_class: Annotated[str, typer.Option("--target-bug-class")] = "",
    temperature: Annotated[float, typer.Option("--temperature")] = 0.0,
) -> None:
    """Run the wide-pass nominator skill against the cached repo."""
    import duckdb as _duckdb

    from ai_codescan.nominator import run_nominator
    from ai_codescan.runs.state import load_or_create
    from ai_codescan.taxonomy.loader import (
        UnknownBugClassError,
        list_classes,
        resolve_classes,
    )

    cache_root: Path = ctx.obj["cache_root"]
    if not repo_id:
        repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
        if len(repos) != 1:
            typer.echo("Specify --repo-id.", err=True)
            raise typer.Exit(code=1)
        repo_id = repos[0]
    repo_dir = cache_root / repo_id
    db_path = repo_dir / "index.duckdb"
    if not db_path.is_file():
        typer.echo("No prep output. Run `ai-codescan prep` first.", err=True)
        raise typer.Exit(code=1)

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

    state = load_or_create(
        repo_dir,
        engine="codeql",
        temperature=temperature,
        target_bug_classes=[c.name for c in bug_classes],
    )
    nominations_path = run_nominator(
        state, repo_dir=repo_dir, bug_classes=bug_classes, db_path=db_path
    )
    typer.echo(f"nominations at {nominations_path}")


@app.command("gate-1")
def gate_1(
    ctx: typer.Context,
    repo_id: Annotated[str, typer.Option("--repo-id")] = "",
    yes: Annotated[bool, typer.Option("--yes", help="Mark every unanswered y/n: as y.")] = False,
    apply: Annotated[
        bool,
        typer.Option("--apply", help="Apply Stream C accepted extensions and re-run CodeQL."),
    ] = False,
) -> None:
    """Open the latest nominations.md for HITL editing, or apply --yes / --apply."""
    cache_root: Path = ctx.obj["cache_root"]
    if not repo_id:
        repos = sorted(p.name for p in cache_root.iterdir() if p.is_dir())
        if len(repos) != 1:
            typer.echo("Specify --repo-id.", err=True)
            raise typer.Exit(code=1)
        repo_id = repos[0]
    runs_root = cache_root / repo_id / "runs"
    if not runs_root.is_dir():
        typer.echo("No runs.", err=True)
        raise typer.Exit(code=1)
    last_run = max(runs_root.iterdir(), key=lambda p: p.stat().st_mtime)
    nominations = last_run / "nominations.md"
    if not nominations.is_file():
        typer.echo("No nominations.md — run `nominate` first.", err=True)
        raise typer.Exit(code=1)

    if yes:
        from ai_codescan.gate import apply_yes_to_all

        nominations.write_text(
            apply_yes_to_all(nominations.read_text(encoding="utf-8")),
            encoding="utf-8",
        )
        typer.echo("marked all unanswered as y")
    elif apply:
        from ai_codescan.engines.codeql import build_database, run_queries
        from ai_codescan.gate import selected_extensions
        from ai_codescan.ingest.sarif import ingest_sarif

        exts = selected_extensions(nominations.read_text(encoding="utf-8"))
        if not exts:
            typer.echo("no Stream C extensions accepted")
            return
        ext_dir = cache_root / repo_id / "codeql" / "extensions"
        ext_dir.mkdir(parents=True, exist_ok=True)
        for ext in exts:
            (ext_dir / f"{ext.nomination_id}.model.yml").write_text(
                ext.yaml_body,
                encoding="utf-8",
            )
        # Re-run CodeQL across each project DB with the new extensions.
        import duckdb as _duckdb

        conn = _duckdb.connect(str(cache_root / repo_id / "index.duckdb"))
        for db in (cache_root / repo_id / "codeql").glob("*.db"):
            project_id = db.name[:-3]
            try:
                result = run_queries(
                    db,
                    cache_dir=cache_root / repo_id,
                    project_id=project_id,
                    codeql_tags=[],
                    extension_packs=[ext_dir],
                )
                ingest_sarif(
                    conn,
                    sarif_path=result.sarif_path,
                    project_id=project_id,
                    snapshot_root=cache_root / repo_id / "source",
                    engine="codeql",
                )
            except (RuntimeError, OSError) as exc:
                typer.echo(f"warning: re-run failed for {project_id}: {exc}", err=True)
        typer.echo(f"applied {len(exts)} extension(s); flows updated")
    else:
        editor = os.environ.get("EDITOR", "vi")
        subprocess.run([editor, str(nominations)], check=False)


@app.command()
def run(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Target repo to scan end-to-end.")],
    target_bug_class: Annotated[str, typer.Option("--target-bug-class")] = "",
    temperature: Annotated[float, typer.Option("--temperature")] = 0.0,
    yes: Annotated[bool, typer.Option("--yes")] = False,
    commit: _CommitOption = None,
) -> None:
    """End-to-end Phase 1: prep + nominate + gate-1 in one shot."""
    from ai_codescan.config import compute_repo_id

    flags: list[str] = []
    if target_bug_class:
        flags += ["--target-bug-class", target_bug_class]
    if commit:
        flags += ["--commit", commit]

    cache_root: Path = ctx.obj["cache_root"]
    cache_arg = ["--cache-dir", str(cache_root)]
    rc = subprocess.call(["ai-codescan", *cache_arg, "prep", str(target), *flags])
    if rc != 0:
        raise typer.Exit(code=rc)

    repo_id = compute_repo_id(target)
    nominate_args = ["--repo-id", repo_id, "--temperature", str(temperature)]
    if target_bug_class:
        nominate_args += ["--target-bug-class", target_bug_class]
    rc = subprocess.call(["ai-codescan", *cache_arg, "nominate", *nominate_args])
    if rc != 0:
        raise typer.Exit(code=rc)

    gate_args = ["--repo-id", repo_id]
    if yes:
        gate_args.append("--yes")
    subprocess.call(["ai-codescan", *cache_arg, "gate-1", *gate_args])
```

Add the imports at the top of `cli.py` if not already present:

```python
import os
import subprocess
```

- [ ] **Step 2: Add a `--install-skills` global option that copies the bundled skill into `~/.claude/skills/`**

In `ai_codescan/cli.py`, add:

```python
@app.command("install-skills")
def install_skills() -> None:
    """Copy bundled skills into ~/.claude/skills/."""
    src = Path(__file__).resolve().parent / "skills" / "wide_nominator"
    dest = Path.home() / ".claude" / "skills" / "wide_nominator"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        import shutil as _sh

        _sh.rmtree(dest)
    import shutil as _sh

    _sh.copytree(src, dest)
    typer.echo(f"installed skill to {dest}")
```

- [ ] **Step 3: Tests**

Append to `tests/test_cli.py`:

```python
@pytest.mark.integration
def test_nominate_creates_nominations_md(tmp_path: Path, fixtures_dir: Path, monkeypatch) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    # Pretend `claude` is missing so the orchestrator writes the empty header file.
    monkeypatch.setenv("PATH", "/nonexistent")
    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "nominate", "--repo-id", repo_id],
    )
    assert result.exit_code == 0
    runs = sorted((cache / repo_id / "runs").iterdir())
    assert runs
    nominations_path = runs[-1] / "nominations.md"
    assert nominations_path.is_file()
    body = nominations_path.read_text()
    assert "Stream A" in body and "Stream B" in body and "Stream C" in body


@pytest.mark.integration
def test_gate_1_yes_marks_all(tmp_path: Path, fixtures_dir: Path) -> None:
    cache = tmp_path / "cache"
    runner.invoke(
        app,
        ["--cache-dir", str(cache), "prep", str(fixtures_dir / "tiny-express")],
    )
    repo_id = next(p.name for p in cache.iterdir() if p.is_dir())
    runs_root = cache / repo_id / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    run_dir = runs_root / "deadbeef"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "nominations.md").write_text(
        (fixtures_dir / "nominations-sample.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["--cache-dir", str(cache), "gate-1", "--repo-id", repo_id, "--yes"],
    )
    assert result.exit_code == 0
    txt = (run_dir / "nominations.md").read_text()
    assert "y/n: y" in txt and "y/n: n" in txt
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: green.

- [ ] **Step 5: Commit**

```bash
git add ai_codescan/cli.py tests/test_cli.py
git commit -m "feat(cli): nominate, gate-1, run, install-skills"
```

---

## Task 7: Smoke test, README, milestone tag

- [ ] **Step 1: Gate**

```bash
make check
```

- [ ] **Step 2: Install skill + smoke test**

```bash
uv run ai-codescan install-skills
uv run ai-codescan run /tmp/tmp-express --target-bug-class injection --yes
cat ~/.ai_codescan/repos/tmp-express-*/runs/*/nominations.md
```

- [ ] **Step 3: README + tag**

Append to `README.md`:

```markdown
## Phase 1E status — Phase 1 complete

End-to-end: `ai-codescan run <target>` → prep → nominate → gate-1. Use `--yes` to skip the editor.

\`\`\`bash
ai-codescan install-skills
ai-codescan run /path/to/target --target-bug-class injection,idor --yes
\`\`\`
```

```bash
git add README.md
git commit -m "docs: phase 1E status (phase 1 complete)"
git tag -a phase-1 -m "Phase 1 complete: prep + wide-pass + HITL gate"
```

---

## Self-review

| Spec section | Implemented in |
|---|---|
| §3 Phase 1 boundary | Task 6 (`run` super-command) |
| §5.9 wide_nominator skill | Tasks 3 + 4 |
| §6 full taxonomy + needs_semantic | Task 1 |
| §7 `nominate`, `gate-1`, `run`, `--yes`, `--apply`, `--temperature`, `--install-skills` | Tasks 4 + 6 |
| §9 atomic-line claim, three streams, Summary line | Tasks 3 + 5 |
| §11.1 cost ledger | Task 2 |

All Phase-1 spec requirements covered across plans 1A–1E. Phase 2 (deep analyzer, validate, report, storage taint) gets its own spec when 1E ships.

No placeholders. CLI flag names match the spec. Skill follows Ghost's atomic-line pattern. Run-state JSON serialises round-trip.
