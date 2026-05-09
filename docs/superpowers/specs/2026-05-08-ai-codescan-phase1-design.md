# AI_Codescan — Phase 1 Design

**Status:** Brainstormed, ready for implementation planning
**Date:** 2026-05-08
**Scope:** Phase 1 (Prep + Wide pass). Phase 2 (Deep + Validate + Report) is sketched at the end and gets its own spec when Phase 1 ships.

---

## 1. Goal

Build a reproducible, AI-assisted source-code analysis pipeline that finds security bugs in target codebases. Day-one languages: JavaScript, TypeScript, HTML. Architecture is pluggable so Python, Java/Kotlin, C#, Go, PHP can drop in later (priority order driven by corporate footprint and bug-bounty prevalence).

Built clean, inspired by Ghost skills' loop pattern. Every successful 2024–2026 system in the literature (IRIS, GPTScan, LLMxCPG, LATTE, Slice, Fraim, Vulnhuntr, Aardvark) is **hybrid**: deterministic static analysis feeds a *pre-sliced* context to an LLM. We follow that consensus.

## 2. Non-goals

- Running against compiled binaries (RE patterns are borrowed for navigation, not for analysis).
- Replacing existing Ghost skills wholesale — separate lifecycle, own conventions.
- Multi-service / cross-repo taint tracing (Phase 3+).
- IDE plugins. The CLI is the surface; views are file-based.
- Full automation. HITL gates are the default; `--yes` exists but is opt-in.

## 3. Phasing

**Phase 1 (this spec).** Deterministic prep + wide nominator + HITL Gate 1. Output is a triaged candidate list a human can hand-review and either ship to Phase 2 or close.

**Phase 2 (next spec, after Phase 1 ships).** Deep analyzer (Opus sub-agent per accepted item, isolated context) + HITL Gate 2 + validator (with optional sandbox PoC) + HITL Gate 3 + report. Layer 5 storage-taint analysis lives here. `--engine llm-heavy` (Aardvark-style) lives here.

**Phase 3 (future).** `--engine hybrid` (CodeQL ∪ Joern ∪ Semgrep, dedupe). Cross-process / multi-service flows.

## 4. Architecture

### 4.1 Phase 1 dataflow

```
target_repo
    │
    ▼
┌─────────────────────────────────────────────────┐
│ scan prep   (Python, deterministic)             │
│   ├─ snapshot via git worktree (or cp + hash)   │
│   ├─ stack detect → repo.md                     │
│   ├─ ts-morph + parse5 + tree-sitter → AST      │
│   ├─ scip-typescript → SCIP index               │
│   ├─ CodeQL DB build (--engine codeql)          │
│   ├─ CodeQL run → SARIF                         │
│   ├─ ingest into DuckDB index + sidecar JSONL   │
│   └─ entrypoints.md                             │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│ wide nominator   (Claude skill, Batch API)      │
│   reads cached repo snapshot + sidecar JSONL    │
│   emits nominations.md (Streams A/B/C) with     │
│   per-item Summary + ai-rec + "y/n: " HITL line │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│ HITL Gate 1                                     │
│   user marks y/n; or `gate-1 --yes` shortcut    │
│   Stream C accepted → CodeQL re-run with new    │
│   model extensions; new flows feed back into A  │
└─────────────────────────────────────────────────┘
    │
    ▼  Phase 1 ends. Approved candidates ready for Phase 2.
```

### 4.2 Engine modes

- `--engine codeql` — default; CodeQL DB build + SARIF flows. Phase 1 only supports this mode.
- `--engine llm-heavy` — Phase 2 only. Skips CodeQL; LLM walks via SCIP/LSP tools (Aardvark pattern). Uses Opus-tier models.
- `--engine hybrid` — Phase 3+. Both engines, dedupe on `(source_symbol, sink_symbol)`.

The flag is a top-level pipeline arg; downstream phases consume the same `flows.jsonl` regardless of producer.

### 4.3 Source enrichment — the four-layer stack (Phase 1)

| Layer | What | Where |
|---|---|---|
| 0 | **Source snapshot** (read-only enforced via filesystem permissions). Git worktree if possible (`git worktree add <cache>/source <commit>` — cheap, pinned, shares objects), else `cp -r` + content-hash manifest. | `<cache>/source/` |
| 1 | **Stable symbol IDs.** Use SCIP's symbol scheme (`scip-typescript npm <pkg> <ver> ` `<relpath>`/`<scope>`/`<name>`#`<member>.`). Stable across renames within a commit; deterministic re-emit. Re-index per commit. Fallback for non-SCIP nodes (HTML inline scripts, dynamic eval): content-hash ID `sha1(relpath + ast_path + token_text)[:12]`. | embedded in every other layer |
| 2 | **Sidecar JSONL per file.** One record per symbol/source/sink/call/flow. Append-only within a phase. Schema in §5.6. | `<cache>/source/**/*.enrich.jsonl` (regenerable from DuckDB) |
| 3 | **DuckDB master index.** Normalized tables: `files`, `symbols`, `xrefs`, `taint_sources`, `taint_sinks`, `flows`, `notes`, `entrypoints`. Survives between phases like an IDA `.idb`. SQL joins answer source↔sink queries in <100 ms. | `<cache>/index.duckdb` |
| 4 | **Annotated source view (derived).** Generated on demand from JSONL/DuckDB; never the source of truth. For human review and diff-between-commits inspection. | `<cache>/views/<commit>/<relpath>.annotated.md` |

Layer 5 — storage taint (stored/async second-order taint, schema annotation file, two-pass fixpoint over write/read storage locations) — is **deferred to Phase 2**. The DuckDB schema reserves slots for it (`storage_locations`, `storage_writes`, `storage_reads`, `storage_taint`) but Phase 1 does not populate them.

### 4.4 IDA/Ghidra patterns folded in

| RE pattern | Source-analysis equivalent | Where |
|---|---|---|
| Bidirectional xrefs | `xrefs` table populated by CodeQL + SCIP + LSP | DuckDB |
| Layered comments (auto / repeatable / human) | `notes(symbol_id, layer, author)` | DuckDB |
| Bookmarks | `notes` row with `pinned=true` | DuckDB |
| Rename propagation | LLM updates `symbols.display_name`; views regenerate | JSONL + view regen |
| Triage: imports / strings / entry points | Prep emits `entrypoints.md` (routes, listeners, CLI args, message queues, cron) | Prep output |
| Persistent project DB | `index.duckdb` survives re-runs; cache-aware | DuckDB |
| Diff between commits (BinDiff / Diaphora) | Two commits → two DBs → `flows_diff` view: new sinks, new flows, removed sanitizers | DuckDB query, exposed as `ai-codescan diff` |

## 5. Components (Phase 1)

### 5.1 `ai_codescan/snapshot.py`
**In:** target repo path, output cache dir
**Out:** read-only snapshot under `<cache>/source/`, `manifest.jsonl` (`path`, `sha256`, `size`, `mtime`)
**Behavior:** `git worktree add` if repo is git, else `cp -r`. Sets read-only bits. Detects "no change since last manifest" → skip downstream re-prep. Snapshot is **read-only** during a scan; agents can't accidentally mutate it.

### 5.2 `ai_codescan/stack_detect.py`
**In:** snapshot path
**Out:** `<cache>/repo.md` — projects detected, languages, frameworks (Express/Next/React/Vue/Svelte/etc.), package manager, monorepo layout, `tsconfig` reference graph
**Behavior:** Heuristic match on `package.json`, lockfiles, framework markers. One "project" entry per logical unit.

### 5.3 `ai_codescan/ast/ts.py` + `ai_codescan/ast/html.py`
**In:** project entry, snapshot path
**Out:** raw AST JSONL per file under `<cache>/ast/<relpath>.jsonl`
**Behavior:**
- `ts-morph` (real types via TS checker) for `.ts`/`.tsx`/`.js`/`.jsx` inside any tsconfig.
- `parse5` for HTML — splices `<script>` bodies and event-handler attrs as virtual TS sources sharing a single AST namespace with linked `.js`.
- `tree-sitter-typescript` / `tree-sitter-tsx` as a parse-only fallback for files outside any tsconfig, `.vue`/`.svelte` SFCs (community grammars), or malformed code.
- Drives a Node worker via subprocess for ts-morph; emits JSON. Pinned versions for reproducibility.
- For `.vue` / `.svelte`: use the official Volar / svelte preprocessors to extract `<script lang="ts">` blocks to virtual `.ts` files, then feed those to ts-morph.

### 5.4 `ai_codescan/index/scip.py`
**In:** project entry
**Out:** `<cache>/scip/<project_id>.scip` (binary protobuf)
**Behavior:** invokes `scip-typescript index --infer-tsconfig`. Parsed via Python protobuf bindings into DuckDB. Symbol IDs from this output drive Layer 1.

### 5.5 `ai_codescan/engines/codeql.py`
**In:** project entry, snapshot
**Out:** `<cache>/codeql/<project_id>.db/`, `<cache>/codeql/<project_id>.sarif`
**Behavior:**
- `codeql database create --language=javascript-typescript`.
- Runs `security-extended` + `security-and-quality` query suites.
- SARIF includes full `codeFlows` / `threadFlows`.
- Models-as-data extension dir `<cache>/codeql/extensions/` for user/LLM-added sources/sinks (sanitizers/barriers in YAML — no QL writing for most overrides since CodeQL CLI 2.25).
- For minified-bundle targets: set `CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES=true` (CodeQL 2.24+ skips them by default).
- Filtered to query tags matching the user's `--target-bug-class` selection.

### 5.6 `ai_codescan/index/duckdb.py`
**In:** SCIP file, SARIF file, AST JSONL
**Out:** `<cache>/index.duckdb` populated

**Tables (Phase 1):**

```sql
files(path, sha256, lang, project_id, size)

symbols(id, sym, kind, file, range_start, range_end, type, display_name)
  -- sym = SCIP ID, fallback content-hash

xrefs(caller_id, callee_id, kind)
  -- kind ∈ 'call' | 'reference' | 'implementation'

taint_sources(tid, symbol_id, class, key, evidence_loc)

taint_sinks(sid, symbol_id, class, lib, parameterization, tainted_slots_json)

flows(fid, tid, sid, cwe, engine, steps_json, sarif_ref, confidence)
  -- engine ∈ 'codeql' | 'ai-proposed-inferred' | 'ai-proposed-model-extension'
  -- confidence ∈ 'definite' | 'inferred' | 'llm-suggested'

notes(symbol_id, layer, author, content, pinned, ts)
  -- layer ∈ 'auto' | 'agent' | 'human'

entrypoints(symbol_id, kind, signature)
  -- kind ∈ 'http_route' | 'listener' | 'cron' | 'cli' | 'message_consumer'

-- taint_sinks.parameterization ∈ 'parameterized' | 'template-literal' | 'string-concat' | 'orm-builder' | 'unknown'
-- taint_sources.class examples: 'http.body' | 'http.params' | 'http.query' | 'http.headers' | 'cli.argv' | 'env' | 'file.read' | 'queue.consume' | 'cache.read'
-- taint_sinks.class examples: 'sql.exec' | 'cmd.exec' | 'fs.write' | 'fs.read' | 'http.outbound' | 'html.write' | 'eval' | 'redirect'
```

**Phase 2 reserved tables:** `storage_locations`, `storage_writes`, `storage_reads`, `storage_taint`.

**Materialized views:**

```sql
v_sources_to_sinks(source_symbol_id, sink_symbol_id, fids, cwes)
  -- "given a source, all sinks reached"

v_sinks_from_sources(sink_symbol_id, source_symbol_id, fids, cwes)
  -- "given a sink, all sources flowing into it"
```

### 5.7 `ai_codescan/sidecars.py`
**In:** DuckDB index, file path
**Out:** `<cache>/source/**/*.enrich.jsonl` (regenerable from DuckDB)
**Behavior:** projects per-file slices of the index for cheap per-file LLM consumption. Schema example:

```jsonl
{"id":"S1","kind":"function","sym":"…/app.ts/handler#","range":[12,18],"params":["req","res"],"framework":{"type":"express.route","method":"POST","path":"/users"}}
{"id":"B1","kind":"binding","sym":"…/handler/name#","range":[13,13],"type":"string","taint":{"role":"source","class":"http.body","key":"name","tid":"T-001"}}
{"id":"C2","kind":"call","callee":"…/db.ts/saveUser#","range":[16,16],"taint_in":[{"arg":0,"taint_state":[{"path":".name","tid":"T-001"}]}]}
{"id":"K1","kind":"sink","sym":"…/db.ts/saveUser/conn.query@5#","range":[5,5],"sink":{"class":"sql.exec","lib":"pg","parameterization":"template-literal","tainted_slots":[{"slot":0,"path":"user.name"}]}}
{"id":"F1","kind":"flow","source_tid":"T-001","sink_id":"K1","cwe":"CWE-89","steps":["B1","C1","C2","K1"],"engine":"codeql"}
```

### 5.8 `ai_codescan/views.py`
**In:** DuckDB, file or symbol query
**Out:** `<cache>/views/<commit>/<relpath>.annotated.md` (or stdout)
**Behavior:** generates rendered annotated source view on demand. Markdown with code-fenced source + inline annotations like `// [B1] ⊕ SOURCE T-001 http.body`. Equivalent to Hex-Rays decompilation re-rendered from the IDB.

### 5.9 `ai_codescan/skills/wide_nominator/` (Claude Code skill)

Shipped as part of the Python package under `ai_codescan/skills/` and installed into the user's Claude Code skill path on first run (`ai-codescan --install-skills`). The CLI invokes the skill non-interactively by calling `claude -p` with the skill name; the skill is also discoverable manually inside Claude Code (`/wide-nominator`).

```
skills/wide_nominator/
├─ SKILL.md                          # frontmatter + workflow
├─ prompts/
│  └─ nominator.md                   # the iteration body (one item per call)
└─ scripts/
   └─ loop.sh                        # Ghost-style atomic-line claim loop
```

**Inputs (cached + cache-controlled in the prompt):**

1. `repo.md` — stack/framework context.
2. `entrypoints.md` — every place user input enters the system.
3. DuckDB query results (run once, embedded in prompt):
   - All `flows` grouped by sink class — these are CodeQL-traced and ready for triage (Stream A).
   - All `taint_sinks` with no associated `flow` — suspicious sinks nothing reaches (often = missed source models).
   - All `taint_sources` with no downstream sink — interesting if user thinks they should reach somewhere.
   - All `entrypoints` with no associated taint source — user input the analyzer didn't track.
   - Authz/authn callsite heuristic matches (middleware chains, decorators, `req.user` access patterns).
   - Top-N most-called functions (hotspot prior).
4. Sidecar JSONL slices for any file referenced above.
5. The bug-class filter set.

**Outputs — `nominations.md` has three streams:**

```
## Stream A — Pre-traced (CodeQL flows ready for triage)
- [ ] N-001 | api | sqli | src/users.ts:42 | rec: high | y/n: 
    Summary: Likely SQLi in `id` from URL path when fetching a user — flows
             unparameterised into pg.query template literal.
    Flows: F12, F87 (CWE-89, template-literal)
    Source T-002 (req.params.id @ users.ts:13) → makeUser arg 1 → query slot 1
    Engine: codeql (definite)

## Stream B — AI-discovered candidates (no static flow exists; semantic concern)
- [ ] N-014 | api | idor | src/orders.ts:58 | rec: med | y/n: 
    Summary: Possible IDOR — handler returns any order by id without checking
             the order belongs to the requesting user.
    Heuristic: req.params.orderId → Order.findOne; no req.user.id comparison.
    Symbols: getOrder@orders.ts, Order.findOne@db.ts (via xrefs)
    Engine: ai-proposed (inferred)

## Stream C — Proposed CodeQL model extensions (IRIS pattern)
- [ ] N-022 | api | model-proposal | extensions/bullmq.model.yml | rec: high | y/n: 
    Summary: Library `bullmq` (queue) is unmodelled by CodeQL — proposing
             source/sink models could surface new flows on re-run.
    Proposed model: jobs.add(payload) → sink class queue.publish; ...
    Engine: ai-proposed (model-extension)
```

**Summary line contract:** max 2 lines, plain English, no symbol IDs / file paths / jargon. The structured fields are the fallback.

**Driver:** Batch API for cost (50% off, ≤100K req / 256MB / 24 h). `cache_control` breakpoints at (tools | system | repo.md | entrypoints.md). Sub-agent isolation per item not used in Phase 1 — that's Phase 2 deep-pass territory.

**Loop:** Ghost-style atomic-line claim. `loop.sh` `grep`s for `^- \[ \]`, claims one item, calls `claude -p` with the slot's evidence, flips to `[x]` on success, `[!]` on failure (retried up to 3×). 10-minute per-call timeout; resumes on re-invocation.

### 5.10 `ai_codescan/cli.py`

Entry binary `ai-codescan`. See §7.

### 5.11 `ai_codescan/taxonomy/bug_classes.yaml`

See §6.

## 6. Bug-class taxonomy

Single source of truth: `ai_codescan/taxonomy/bug_classes.yaml`. Drives the CLI flag, the prompt scoping, and `--list-bug-classes`.

### 6.1 Schema

```yaml
xss:
  cwes: [CWE-79]
  codeql_tags: [security/cwe/cwe-079]
  group: injection
  description: "Cross-site scripting (reflected, stored, DOM)"
  subclasses: [reflected-xss, stored-xss, dom-xss, mxss]

sqli:
  aliases: [sql-injection]
  cwes: [CWE-89]
  codeql_tags: [security/cwe/cwe-089]
  group: injection

idor:
  aliases: [bola]
  cwes: [CWE-639]
  group: authz
  needs_semantic: true   # no static sink model — always Stream B
```

### 6.2 Initial entries

`xss`, `sqli`, `nosqli`, `cmdi` (aliases: `command-injection`, `os-cmdi`), `code-injection`, `ssti` (alias: `template-injection`), `prompt-injection`, `xxe` (alias: `xml-external-entity`), `ldap-injection`, `path-traversal` (alias: `dir-traversal`), `lfi`, `rfi`, `ssrf`, `csrf`, `idor` (alias: `bola`), `bfla`, `mass-assignment`, `open-redirect`, `cors-misconfig`, `crlf-injection` (alias: `header-injection`), `unsafe-deserialization` (alias: `insec-deser`), `prototype-pollution`, `redos` (alias: `regex-dos`), `auth-bypass` (alias: `broken-authn`), `weak-crypto`, `insecure-random`, `jwt-misuse`, `session-fixation`, `host-header-injection`, `request-smuggling`, `cache-poisoning`, `info-disclosure`, `dom-clobbering`, `client-side-redirect`, `oauth-misconfig`.

### 6.3 Groups

```yaml
groups:
  injection:       [xss, sqli, nosqli, cmdi, code-injection, ssti, xxe, ldap-injection, prompt-injection, crlf-injection]
  file:            [path-traversal, lfi, rfi]
  authz:           [idor, bfla, mass-assignment]
  authn:           [auth-bypass, jwt-misuse]
  request-forgery: [ssrf, csrf]
  crypto:          [weak-crypto, insecure-random]
  web-config:      [cors-misconfig, host-header-injection, request-smuggling, cache-poisoning, oauth-misconfig]
  serialization:   [unsafe-deserialization]
  javascript:      [prototype-pollution, dom-clobbering]
  redirect:        [open-redirect, client-side-redirect]
  dos:             [redos]
  data-exposure:   [info-disclosure]
  all-injection:   ['@injection', '@file', '@serialization']   # nested groups
```

### 6.4 CLI behavior

```bash
ai-codescan list-bug-classes              # print full table
ai-codescan list-bug-classes --group authz
ai-codescan prep . --target-bug-class xss,sqli,idor,ssrf
ai-codescan prep . --target-bug-class injection      # group expansion
ai-codescan prep . --target-bug-class @injection,idor
```

- **Autocomplete:** Typer-generated shell completion. `ai-codescan --install-completion zsh` (or bash, fish). After install, `--target-bug-class <TAB>` lists names + groups + aliases.
- **Bad input:** unknown name → Levenshtein-suggest closest match, exit non-zero.
- **Filter effect:**
  - CodeQL run filtered to union of `codeql_tags` for selected classes.
  - Nominator prompt scoped to those classes only.
  - `needs_semantic: true` classes (idor, bfla) always run AI Stream B regardless.

## 7. CLI surface

```bash
# Setup
ai-codescan --install-completion zsh

# One-shot end of Phase 1
ai-codescan run <target>

# Granular
ai-codescan prep <target>
ai-codescan nominate
ai-codescan gate-1
ai-codescan gate-1 --yes
ai-codescan gate-1 --apply       # apply Stream C accepted extensions; re-run CodeQL

# Inspection
ai-codescan list-bug-classes [--group <g>]
ai-codescan view <symbol>
ai-codescan view --file <path>
ai-codescan query "<sql>"
ai-codescan flows --from <symbol>
ai-codescan flows --to <symbol>
ai-codescan status
ai-codescan diff <commit-a> <commit-b>

# Maintenance
ai-codescan cache list
ai-codescan cache rm <repo_id>
ai-codescan cache gc

# Phase 2 subcommands (placeholder, not implemented in Phase 1)
ai-codescan analyze              # deep
ai-codescan gate-2
ai-codescan validate
ai-codescan gate-3
ai-codescan report
```

### Flags (Phase 1)

| Flag | Default | Purpose |
|---|---|---|
| `--engine` | `codeql` | Phase 1 only supports `codeql`; `llm-heavy` and `hybrid` reserved for later phases |
| `--target-bug-class` | (all) | Comma-separated taxonomy names or `@group`; completion-aware |
| `--report-dir` | `./report/` | Where Phase 2 will drop final reports |
| `--cache-dir` | `~/.ai_codescan/repos/<id>/` | Where snapshots, indexes, runs live |
| `--commit` | `HEAD` | Pin snapshot to a specific commit |
| `--yes` | off | Skip HITL gates |
| `--cost-cap` | none | Abort phase if exceeded |
| `--temperature` | `0.0` | LLM temperature for nominator and other shallow calls |
| `--temperature-deep` | `0.0` | Phase-2 deep-analyzer temperature (forward-compat; ignored in Phase 1) |
| `--quiet` / `--verbose` | normal | Logging |

Implementation: Typer (rich help, automatic completion, type hints).

## 8. Cache layout

```
<cache>/repos/<repo_id>/
├─ source/                                 # snapshot (git worktree or copy)
├─ manifest.jsonl                          # {path, sha256, size, mtime}
├─ repo.md                                 # stack/framework detection
├─ entrypoints.md                          # routes, listeners, cron, CLI, queues
├─ ast/<relpath>.jsonl                     # ts-morph + parse5 + tree-sitter
├─ scip/<project_id>.scip                  # scip-typescript binary protobuf
├─ codeql/
│   ├─ <project_id>.db/
│   ├─ <project_id>.sarif
│   └─ extensions/                         # models-as-data YAML (user + LLM-suggested)
├─ index.duckdb                            # the project DB
├─ source/**/*.enrich.jsonl                # per-file sidecars (regenerable)
├─ runs/<run_id>/
│   ├─ run.json                            # config, flags, target_bug_classes, cost ledger
│   ├─ nominations.md                      # Stream A/B/C with HITL y/n: lines
│   └─ logs/
└─ views/<commit>/<relpath>.annotated.md   # generated views (optional)
```

`repo_id` = `<basename>-<sha1(remote_url-or-abspath)[:8]>`. Borrowed from Ghost; lets multiple targets coexist.

## 9. State-file conventions

Every gate file uses Ghost's atomic-line pattern. One item per line. Agents only flip `[ ]` → `[x]`; humans only flip `y/n:`. No prose mutation.

```
- [ ] N-001 | api | sqli | src/users.ts:42 | rec: high | y/n: 
    Summary: Likely SQLi in `id` from URL path when fetching a user.
    Flows: F12, F87
    ...
```

`yes-to-all`: `ai-codescan gate-1 --yes` applies a single `sed` over all unmarked items.

## 10. Resumability

Every step is idempotent and writes its output atomically (write-temp + rename). On re-invocation:

1. `manifest.jsonl` diff vs current snapshot → list of changed files.
2. For unchanged files, all downstream artifacts remain valid.
3. For changed files, invalidate `symbols`, `xrefs`, `taint_sources`, `taint_sinks`, `flows` rows where `file IN changed_paths`, plus transitively any flow whose `steps` touch those files.
4. Re-run AST extraction; SCIP re-index per affected project; CodeQL re-extract those files + re-query.
5. Re-run nominator only over candidates whose evidence changed.

Crash mid-step: `runs/<id>/run.json` records current phase; resume from last completed step.

## 11. Cost, errors, testing, reproducibility

### 11.1 Cost ledger

`runs/<id>/run.json` accumulates an itemized cost record:

```json
{
  "phase": "nominate",
  "calls": [
    {"step": "batch:nominator", "model": "claude-sonnet-4-6",
     "input_tokens": 130000, "cache_read": 120000, "output_tokens": 8000, "usd": 0.42}
  ],
  "total_usd": 0.42
}
```

- Pre-run estimate from prep stats (file count, sink count, flow count). Display before phase.
- `--cost-cap` aborts cleanly mid-phase, marking incomplete items as `- [ ]` so resume picks them up.
- `ai-codescan status` prints rolling totals.

### 11.2 Error handling

- Every external tool wrapped with retry+backoff and structured logging.
- **CodeQL failure** (often: monorepo OOM): catch, downgrade to per-project DBs, retry. Persistent failure → mark project `codeql_status: failed` in `repo.md`, continue with partial coverage; surface in nominations as a warning.
- **LSP / scip-typescript hang:** per-call 60 s timeout; kill subprocess; record skipped symbols; do not block downstream steps.
- **Subprocess sandboxing:** target source is treated as untrusted. Every external tool runs with `npm config set ignore-scripts true` and no network. Containerization (Docker / Podman) is the recommended deploy; rootless and with `--network=none`. Disable `tsconfig.json` `extends` of remote URLs in the prep step (rewrite to local paths or fail loudly).
- **Agent failures:** `loop.sh` claims items atomically; failed item rewrites `[x]` → `[!]` with error annotation, agent retries up to 3× then leaves for manual.

### 11.3 Testing strategy

- **Fixture targets** under `ai_codescan/tests/fixtures/` — small intentionally-vulnerable Express/Next/React snippets with known flows. CI runs `prep` + `nominate` against each; asserts presence of expected nominations by `(file, line, vector)`, not text equality.
- **Determinism tests** (when `--temperature 0.0`): run prep twice on same fixture; DuckDB content must hash-match modulo timestamps. Determinism contract loosens when temperature > 0: cost regression bounds widen to ±25%, golden snapshots disabled, content-hashed nomination IDs still stable.
- **Cost regression test:** assert nominator token usage stays within ±10% across runs (catches accidental cache-key drift).
- **Real-target smoke test:** nightly run against one or two open-source bug-bounty targets with known flows; track recall.
- **Mutation testing** on bug-class taxonomy resolver and DuckDB ingestion (pure logic, high blast radius).

### 11.4 Reproducibility

- All external tools pinned by version: `codeql-cli`, `node`, `typescript`, `ts-morph`, `parse5`, `scip-typescript`, `tree-sitter-typescript`, `tree-sitter-tsx`. Captured in `pyproject.toml` + a `tools.lock` file with binary SHA256s.
- LLM determinism: `temperature=0.0` default; `seed` set per phase. Cache breakpoints stable across runs.
- Snapshot pinning: `--commit <sha>` for git targets; manifest hash for non-git.
- Output stable-sorted: nomination IDs assigned by content hash of `(project, vector, file, line, symbol)` so reruns produce identical IDs for identical findings.

## 12. Open questions / Phase 2 outline

The following are intentionally deferred to Phase 2's spec:

- **Layer 5 — Storage taint** (stored / async second-order taint). Two-pass fixpoint over write/read storage locations (SQL columns, ORM models, cache keys, queue topics, file paths, env vars, config keys). LLM wired into 3 decision points: schema-field semantic tagging, ambiguous storage-id proposal, cross-storage chain validation. `schema.taint.yml` as the persistent type library (IDA `.til` analogue).
- **Deep analyzer.** Per-finding Opus sub-agent, isolated context. Symbol-on-demand retrieval (Vulnhuntr pattern). Slice-first / classify-second (LLMxCPG / LATTE pattern, 67–91% token reduction).
- **Validator.** Optional sandbox PoC runner (Aardvark pattern) for high-confidence findings. Container with no network, dropped capabilities.
- **Report templating.** Python templating + LLM polish. Drops into `./report/` (default) or `--report-dir <path>`. Bugbounty/CLAUDE.md filename convention `YYYY-MM-DD--<severity>--<vuln-class>--<component>.md` is opt-in.
- **`--engine llm-heavy`** (Aardvark-style; LSP + SCIP only, LLM walks flows itself).
- **`--engine hybrid`** (CodeQL ∪ Joern ∪ Semgrep, dedupe).
- **Language expansion order:** Python (basedpyright + scip-python + CodeQL), Java/Kotlin (jdtls + scip-java + CodeQL), C# (Roslyn + scip-dotnet + CodeQL), Go (gopls + CodeQL), PHP. Each backend implements: parser → AST extractor, SCIP indexer, optional LSP, CodeQL extractor selection.
- **Graphical visualization of AST and taint flows.** Phase 2 or 3 idea, approach TBD. Candidates:
  - Dynamic HTML using a graph library — [React Flow](https://reactflow.dev/) or [Cytoscape.js](https://js.cytoscape.org/) — backed by a small static server reading from `index.duckdb`. Interactive: zoom into a flow, click a node to open the symbol's annotated view, filter by bug class, diff between commits.
  - Static rendering for sharing — [Graphviz](https://graphviz.org/) DOT export of `xrefs` / `flows` subgraphs, or large-image rendering via `dot -Tsvg`/`-Tpng`. Useful in reports.
  - Browser-based decompiler-style view — split-pane source on left, rendered call graph on right with the active flow highlighted (Hex-Rays / Ghidra UX analogue).
  - SARIF viewers for interop — generate a SARIF file consumable by [SARIF Explorer](https://blog.trailofbits.com/2024/03/20/streamline-the-static-analysis-triage-process-with-sarif-explorer/) or VS Code's SARIF extension as a no-code-needed visualization path.

  Decision deferred. The DuckDB + JSONL data model is already graph-shaped, so any of the above can be added without restructuring Phase 1's storage.

## 13. References

### Tooling
- ts-morph: https://github.com/dsherret/ts-morph, https://ts-morph.com/
- parse5: https://github.com/inikulin/parse5
- tree-sitter: https://github.com/tree-sitter/tree-sitter-typescript
- scip-typescript: https://github.com/sourcegraph/scip-typescript
- SCIP: https://github.com/sourcegraph/scip, https://sourcegraph.com/blog/announcing-scip
- CodeQL CLI: https://docs.github.com/en/code-security/codeql-cli, https://codeql.github.com/docs/
- Joern: https://github.com/joernio/joern, https://docs.joern.io/
- Semgrep: https://semgrep.dev/docs/
- typescript-language-server: https://github.com/typescript-language-server/typescript-language-server
- multilspy: https://github.com/microsoft/multilspy
- DuckDB: https://duckdb.org/
- Typer: https://typer.tiangolo.com/

### Protocols
- LSP 3.17 spec: https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/
- SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- DAP: https://microsoft.github.io/debug-adapter-protocol/specification

### Prior art
- Vulnhuntr (Protect AI): https://github.com/protectai/vulnhuntr
- xvulnhuntr: https://blog.compass-security.com/2025/07/xvulnhuntr/
- GPTScan (ICSE 2024): https://arxiv.org/abs/2308.03314
- IRIS (ICLR 2025): https://arxiv.org/abs/2405.17238
- LLMxCPG (USENIX 2025): https://arxiv.org/abs/2507.16585
- LATTE (TOSEM 2025): https://dl.acm.org/doi/10.1145/3711816
- Slice (CodeQL + LLM): https://noperator.dev/posts/slice/
- Fraim two-stage: https://blog.fraim.dev/optimizing_llm_context_for_vulnerability_scanning/
- sast-ai-workflow (Red Hat): https://github.com/RHEcosystemAppEng/sast-ai-workflow
- OpenAI Aardvark: https://openai.com/index/introducing-aardvark/
- HackerOne Hai Triage: https://www.hackerone.com/press-release/hackerone-unveils-hai-triage-upgraded-ai-powered-vulnerability-response

### Anthropic platform docs
- Prompt caching: https://platform.claude.com/docs/en/docs/build-with-claude/prompt-caching
- Message Batches API: https://platform.claude.com/docs/en/docs/build-with-claude/batch-processing
- Claude Agent SDK: https://code.claude.com/docs/en/agent-sdk/overview

### Inspiration
- Ghost skills: `~/.claude/plugins/cache/ghost-security/ghost/1.1.3/skills/` (loop.sh pattern, criteria YAML, atomic-line markdown state files)
- IDA Pro / Ghidra workflows for navigation, layered comments, persistent project DB, headless batch analysis, BinDiff-style commit diffs
