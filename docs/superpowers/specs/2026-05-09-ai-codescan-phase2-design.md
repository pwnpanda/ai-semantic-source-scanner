# AI_Codescan — Phase 2 Design

**Status:** Pre-authorised by user; building on Phase 1 spec §12.
**Date:** 2026-05-09
**Scope:** Phase 2 — deep analyser, validator with sandbox PoC, report templating, Layer 5 storage taint, `--engine llm-heavy`.

---

## 1. Goal

Take the wide-pass nominations Phase 1 produces and turn them into reproducible, validated bug-bounty-ready findings. Add second-order taint coverage so the pipeline catches stored XSS, queue/cache-borne injection, and cross-request flows. Add an Aardvark-style alternative engine for languages or codebases CodeQL doesn't cover well.

## 2. Phasing within Phase 2

Five sub-plans, each shippable on its own:

| Sub-plan | Output |
|---|---|
| **2A** Deep analyser + Gate 2 | Per-finding Opus sub-agent walks evidence, fills `findings/<id>.md`, status `unverified` |
| **2B** Validator + Gate 3 | Optional Docker-sandboxed PoC runner; flips findings to `verified` / `rejected` |
| **2C** Report templating | Python templating + LLM polish; default `./report/`, opt-in Bugbounty filename convention |
| **2D** Layer 5 storage taint | `schema.taint.yml` + two-pass fixpoint over storage writes/reads |
| **2E** `--engine llm-heavy` | LSP + SCIP only; LLM walks flows itself with `get_symbol` / `find_refs` / `call_hierarchy` tools |

## 3. Architecture

```
              Phase 1 output (nominations.md with y-marked items)
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  Sub-plan 2A — Deep analyser                                    │
│   For each accepted nomination:                                 │
│     • spawn Opus sub-agent (isolated context)                   │
│     • slice extraction (LLMxCPG pattern): pull only the         │
│       source→sink path + influencing variables                  │
│     • symbol-on-demand tools (Vulnhuntr pattern):               │
│       get_symbol, find_refs, call_hierarchy                     │
│     • emit findings/<id>.md with status=unverified              │
│   Atomic-line claim in `findings_queue.md`                      │
│                                  │                              │
│   HITL Gate 2: human prunes / re-prioritises                    │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  Sub-plan 2B — Validator (optional sandbox PoC)                 │
│   For each finding still status=unverified after Gate 2:        │
│     • Docker container: --network=none --cap-drop=ALL           │
│       --read-only --tmpfs /tmp                                  │
│     • install minimal deps from package.json                    │
│     • Opus sub-agent writes a PoC script (Python or JS)         │
│       that exercises the exact path                             │
│     • run inside container; capture stdout/exit code            │
│     • status → verified | rejected | poc_inconclusive           │
│                                  │                              │
│   HITL Gate 3: user signs off                                   │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  Sub-plan 2C — Report templating                                │
│   For each verified finding: render to                          │
│     ./report/YYYY-MM-DD--<sev>--<class>--<component>.md         │
│   Sections: Summary / Severity / Environment / Prereqs /        │
│   Repro Steps / Expected vs Actual / Evidence / Impact /        │
│   Remediation / References                                      │
│   Python builds the skeleton; one LLM polish pass for prose.    │
└─────────────────────────────────────────────────────────────────┘

   ┌───────────────────────────────────────────────────────────────┐
   │  Sub-plan 2D — Layer 5 storage taint (parallel; runs in prep) │
   │   Two-pass fixpoint over storage writes / reads:              │
   │     Round 0 — regular flows (Phase 1)                         │
   │     Round 1 — populate storage_taint from WRITE sinks         │
   │     Round 2 — re-trace flows from READ sources of dirty       │
   │               storage; iterate until stable                   │
   │   Persistent annotation: `<cache>/schema.taint.yml`           │
   │   New CLI: `ai-codescan taint-schema [--edit] [--show]`       │
   └───────────────────────────────────────────────────────────────┘

   ┌───────────────────────────────────────────────────────────────┐
   │  Sub-plan 2E — `--engine llm-heavy`                           │
   │   For codebases CodeQL doesn't cover (or as a sanity check):  │
   │     • SCIP + LSP backbone (already present)                   │
   │     • LLM gets `get_symbol`, `find_refs`, `call_hierarchy`,   │
   │       `read_lines`, `grep_repo` tools                         │
   │     • LLM emits flow records that ingest into the same        │
   │       `flows` table with `engine='llm-heavy'`                 │
   │     • slower, more expensive; behind a flag                   │
   └───────────────────────────────────────────────────────────────┘
```

## 4. Components

### 4.1 `ai_codescan/analyzer.py` (sub-plan 2A)

- `analyze_finding(state, nomination_id) -> FindingResult` — spawns an Opus sub-agent via the LLM provider abstraction (`llm.py`), gives it `get_symbol(id)`, `find_refs(id)`, `call_hierarchy(id)`, `read_lines(file, start, end)` tools, prompts it with the slice + nomination evidence, expects markdown output.
- `extract_slice(conn, flow_id) -> SliceBundle` — pulls source/sink/intermediate steps from `flows.steps_json` and the surrounding ±5 lines for each, builds the LLMxCPG-style minimal slice (drops 67-91% of code per LLMxCPG benchmark).
- Sub-agents claim items atomically from `findings_queue.md`; output to `findings/<finding_id>.md` with frontmatter `status: unverified`.

### 4.2 `ai_codescan/sandbox.py` (sub-plan 2B)

- `validate_in_sandbox(finding_path) -> ValidationResult` — spins up a Docker container with hardened defaults; mounts the snapshot read-only; sub-agent writes `poc.py` (or `.js`) and a single bash invocation; captures `stdout`/`stderr`/`exit_code`/`time`/`exceeded_timeout`.
- Container image: build per-target from `package.json` + the snapshot; cached at `<cache>/sandbox/<project_id>:<commit>`.
- Default env: `--network=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only`, `--tmpfs /tmp:size=128m`, `--memory=512m`, `--cpus=1`, `--pids-limit=64`, timeout 60 s.
- Findings flip to `verified` only if exit_code == 0 AND a configurable signal in stdout (e.g. `OK_VULN`).

### 4.3 `ai_codescan/report.py` (sub-plan 2C)

- `render_report(finding: Finding, *, target_root: Path) -> Path` — renders the markdown report to `./report/YYYY-MM-DD--<sev>--<class>--<component>.md`.
- Severity from CWE → CVSS-like buckets: critical / high / medium / low / informational.
- Component extracted from the symbol's package or topmost path component.
- LLM polish pass: rewrites the prose for clarity but keeps every literal field (CWE, line numbers, commands).
- Bugbounty mode opt-in via `--bugbounty` (writes into the conventional `<target>/report/` per `Bugbounty/CLAUDE.md`).

### 4.4 `ai_codescan/storage_taint.py` (sub-plan 2D)

DuckDB tables already reserved in Phase 1:
- `storage_locations(storage_id, kind, schema_evidence)`
- `storage_writes(storage_id, flow_id, source_tid, symbol_id, call_shape_json)`
- `storage_reads(storage_id, symbol_id, result_binding_id)`
- `storage_taint(storage_id, derived_tid, contributing_tids_json, confidence)`

Resolvers (one per storage class):
| Storage | Resolver | Confidence |
|---|---|---|
| SQL columns | `sqlglot` parse | definite (static SQL) / inferred (dynamic) |
| ORM models | parse `schema.prisma`, TypeORM `@Column`, Sequelize `define`, Mongoose, Drizzle | definite |
| Cache keys | static template analysis on `cache.set/get` | definite (static) / inferred |
| Queue topics | string-flow on `publish`/`subscribe`/`emit` | definite for literals |
| File paths | symbolic execution on `path.join`/`path.resolve` | definite for static parts |
| Env vars | `process.env.X` | definite |
| Config keys | static load of `*.toml`/`*.yaml`/`*.json` | definite |
| Ambiguous | LLM proposes ID; written to `<cache>/llm-suggested-storage.yml` | llm-suggested |

Two-pass fixpoint:
```
Round 0: regular flows (Phase 1) → flows.jsonl
Round 1: enumerate writes; storage_taint[<sql:users.bio>] += T-001
Round 2: every read of dirty storage → fresh source carrying the dirty TIDs
Repeat until storage_taint stable (typically 2 rounds)
```

`schema.taint.yml` format (committed, hand-editable, IDA-`.til` analogue):
```yaml
tables:
  users:
    columns:
      id:            { taint: clean, reason: "auto-generated UUID" }
      bio:           { taint: dirty, sources: [http.body.bio] }
caches:
  redis:
    "user:*:profile": { taint: dirty, sources: [http.body], confidence: definite }
```

LLM is wired in at three exact points:
1. Schema-field semantic tagging — given an ORM model and call sites, label which columns are user-set
2. Ambiguous storage-id proposal — for dynamic keys/topics
3. Cross-storage chain validation — when a derived flow has 3+ stored hops, LLM verifies same-data identity

### 4.5 `ai_codescan/engines/llm_heavy.py` (sub-plan 2E)

- `run_llm_heavy(state, projects) -> list[Flow]` — instead of building a CodeQL DB, gives the Opus sub-agent five tools and asks it to walk flows itself:
  - `get_symbol(id)` — fetch the symbol's source + metadata
  - `find_refs(id)` — list referencing symbols
  - `call_hierarchy(id)` — incoming/outgoing calls
  - `read_lines(file, start, end)` — raw file slice
  - `grep_repo(pattern)` — ripgrep against the snapshot
- Output flows ingest into the same `flows` table with `engine='llm-heavy'`. Confidence: `inferred`.
- Aardvark report achieved 92% recall on golden repos; we expect lower because we're not doing PoC validation in the same loop. Treat as complementary, not replacement.

## 5. Data flow & state files

Every gate file follows the Phase 1 atomic-line convention. Sub-plan 2A adds `findings/<id>.md` files; their frontmatter is the canonical source of truth.

```
<cache>/repos/<repo_id>/runs/<run_id>/
├─ nominations.md             # Phase 1
├─ findings_queue.md          # Phase 2 — one line per accepted nomination
├─ findings/
│   ├─ F-001.md                # status: unverified | verified | rejected
│   └─ ...
└─ report/                    # generated by 2C; or ./report/<...> at CWD
```

## 6. CLI surface (Phase 2 additions)

```bash
ai-codescan analyze [--repo-id X] [--llm-provider P] [--llm-model M] [--temperature T]
ai-codescan gate-2  [--repo-id X] [--yes]
ai-codescan validate [--repo-id X] [--no-sandbox]
ai-codescan gate-3  [--repo-id X] [--yes]
ai-codescan report  [--repo-id X] [--report-dir <path>] [--bugbounty]

# Storage taint (2D):
ai-codescan taint-schema [--show] [--edit]    # opens schema.taint.yml in $EDITOR

# Engine modes (2E):
ai-codescan prep <target> --engine llm-heavy   # alternative to codeql
ai-codescan prep <target> --engine hybrid      # Phase 3 — defer
```

`run` super-command extends to chain prep → nominate → gate-1 → analyze → gate-2 → validate → gate-3 → report.

## 7. Cost, errors, testing, reproducibility

- **Cost ledger** extends `runs/<id>/run.json` — every Opus sub-agent records tokens + USD. Validator includes container build/run time as a proxy for compute cost.
- **Sandbox failures** flip findings to `poc_inconclusive`, not `rejected`. Inconclusive means manual review needed; rejection requires a clear contradicting signal.
- **Layer 5 fixpoint termination**: cap iterations at 5; if not stable, mark the storage location with `confidence: unstable` and surface for review.
- **`--engine llm-heavy` cost cap** strongly recommended (`--cost-cap 50`) to avoid runaway loops.
- Per-component fixture targets under `tests/fixtures/`:
  - `vuln-stored-xss/` — exercise Layer 5 store→read flow
  - `vuln-cmdi-confirmable/` — sandbox PoC produces `OK_VULN`
  - `intentional-fp/` — finding looks tainted but a sanitiser runs; validator must reject

## 8. Open questions deferred to Phase 3

- Hybrid engine (CodeQL ∪ Joern ∪ Semgrep, dedupe) — needs Joern install (~1.5 GB JVM)
- Graphical visualisation — React Flow / Cytoscape / Graphviz / SARIF viewer (UX decision)
- Cross-process / multi-service flows — requires inter-repo source/sink resolution

These are explicitly out of scope for Phase 2.

## 9. References

- Phase 1 spec: `docs/superpowers/specs/2026-05-08-ai-codescan-phase1-design.md` (see §12 — this Phase 2 doc elaborates that outline)
- LLMxCPG (slice-first / classify-second): https://arxiv.org/abs/2507.16585
- Vulnhuntr (symbol-on-demand): https://github.com/protectai/vulnhuntr
- IRIS (LLM-proposed sources/sinks): https://arxiv.org/abs/2405.17238
- Aardvark (sandbox PoC validation): https://openai.com/index/introducing-aardvark/
- Anthropic prompt caching for sub-agent context reuse: https://platform.claude.com/docs/en/docs/build-with-claude/prompt-caching
