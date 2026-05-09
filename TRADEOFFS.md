# Tradeoffs and Autonomous Decisions

This document records every non-obvious decision I made during the
autonomous build of Phases 1–3 so you can review and override anything
that doesn't fit your intent. Tagged milestones (`phase-1`, `phase-2`,
`phase-3a`, `phase-3b`) mark stable points if you want to revert any item.

## Phase 3 — manually flagged decisions you wanted to review

### Joern install — **deferred (NOT installed)**

**Decision:** Wired `--engine hybrid` to call into `engines/joern.py`, but the
actual Joern CLI install was skipped (1.5 GB JVM-based binary). When `joern`
is on PATH, the orchestrator will skip with a clean log line; when absent
(today), the same path is exercised but contributes zero flows.

**Why:** I had explicit autonomy authorization but the Joern install is the
single largest dependency in the project. Better to leave it as an opt-in
install you can choose at scan time than burn ~1.5 GB on this dev machine
without an explicit ask.

**To enable later:**
```bash
curl -L https://github.com/joernio/joern/releases/latest/download/joern-install.sh | bash
# add ~/joern-cli to PATH
```

`engines/joern.py`'s `run_joern` is also a stub — it returns an empty
`<project_id>.flows.jsonl`. The full integration (calling
`joern-parse <root>` and driving a `flows.sc` query that emits JSONL) is
the natural next chunk. Path forward documented in the module docstring.

### Visualization tech — **picked Graphviz**

**Decision:** Rendered flows as a DOT graph; `dot -Tsvg` / `-Tpng` produces
the static image. CLI: `ai-codescan visualize --fmt svg --cwe CWE-89`.

**Why over the alternatives the spec mentioned:**
- **React Flow / Cytoscape.js (interactive HTML):** Would need a small Vite
  server, a build step, and a SCIP→graph adapter. Bigger lift, more moving
  parts, doesn't ship in one binary like `dot`.
- **SARIF Explorer integration:** Free if you already have VS Code; we
  already write SARIF from CodeQL so you can open those today without any
  new code from us.
- **Graphviz:** universally available, scales to thousands of nodes, both
  static images and interactive SVG, no runtime server. Wins on simplicity.

**Tradeoff:** Graphviz layouts get cluttered above ~200 flows. The CLI
default `--limit 200` keeps output legible. Future React Flow work can sit
on top of the same DuckDB index — the data model is unchanged.

## Phase 2 — engineering tradeoffs you should know about

### Layer 5 storage taint — **MVP (round 1 only)**

**What landed:** Storage-location detection (`sql:<table>.<column>`),
write-side recording, and population of `storage_locations` /
`storage_writes` / `storage_taint` tables. SQL parsing via `sqlglot` covers
straightforward INSERT/UPDATE/SELECT.

**What didn't land:** Round 2+ of the fixpoint (re-running the static
engine with synthesised sources at dirty READ sites). The two-pass design
in the spec requires either:
1. Re-emitting CodeQL extension YAMLs that turn dirty columns into sources
   and re-running the analyze step, or
2. A dedicated taint walker over the existing flow graph that crosses the
   "stored taint" boundary.

**Why MVP:** Round 1 is the high-value piece — it identifies the
read/write coupling. Round 2 mostly increases recall on stored-XSS-style
chains but the architecture is in place; it's a follow-up implementation,
not a re-design.

**To extend:** see `storage_taint.run_fixpoint`'s docstring. The natural
chunk is generating CodeQL data-extension YAML from the
`storage_writes` table, dropping it into
`<cache>/codeql/extensions/storage-taint/` and re-running CodeQL from the
hybrid engine.

### Validator sandbox — **Docker-required, soft `--no-sandbox` escape**

**Decision:** `validate` requires Docker by default (hardened flags listed
in `sandbox.py`). `--no-sandbox` falls back to plain local Python, which
is unsafe for genuinely untrusted code; we display the risk in the CLI
help. PoC author writes only Python (`poc.py`) — no JS support yet.

**Tradeoffs:**
- Docker dependency: reasonable for a security-research workstation but
  could be loosened to Podman or Bubblewrap if you want rootless without
  Docker.
- Python-only PoC: covers most flow shapes but JS-heavy targets (Node-only
  exploits) would benefit from a `poc.js` path. Easy follow-up: extend
  `_run_poc` to detect `.js` and run `node poc.js` inside `node:22-alpine`.

### Validator status flip — **rejected vs poc_inconclusive**

**Decision:** PoC exit-code 0 with no `OK_VULN` signal → `rejected`.
Anything else (non-zero exit, timeout) → `poc_inconclusive`.

**Tradeoff:** A PoC that prints `BENIGN` correctly looks the same as a
broken PoC that exits 0 silently. Adding a `BENIGN` literal as a required
signal would tighten this; consider it for v2.

### Deep analyzer — **slice extraction is heuristic**

**Decision:** `_resolve_flow_for_nomination` matches a flow by file-path
substring of the nomination's location. When multiple flows share a file
this picks the first.

**Tradeoff:** Acceptable for files with one flow each (most cases), brittle
when a single file holds many sinks for different bug classes. Better fix:
encode the chosen flow ID in the nomination's metadata and consume it
directly. Easy ~30 line patch.

### `--engine llm-heavy` — **skill ships, no real-world validation yet**

**Decision:** Implementation is fully wired. The skill prompts the LLM to
emit JSONL, the orchestrator ingests, and tests cover the ingest surface.
**But** I haven't run it against a real repo end-to-end — only the
ingestion path is exercised. Cost and quality on a representative
codebase are unknown.

**To validate:** `ai-codescan prep <some-target> --engine llm-heavy
--target-bug-class injection` and inspect `runs/<id>/llm_heavy_flows.jsonl`
plus the resulting DuckDB rows. Expect Aardvark-comparable recall on
small-to-medium projects, but at meaningful Opus token cost.

## Phase 1 — followups completed inline (visible in `phase-1` → `phase-1` tag log)

- ✅ snapshot.py runs `git worktree prune` before `add` (commit `d629fd9`)
- ✅ Sidecars moved from `<cache>/source/**` to `<cache>/sidecars/**` so the
  snapshot stays read-only without W-bit toggling.
- ✅ Entrypoints schema gained `file` + `line` columns; `entrypoints.md` now
  shows real locations instead of `:0`.
- ✅ `compute_repo_id` git-remote path got two new tests.
- ✅ All 158 tests still green at `phase-3b`.

## Decisions still open for your call

1. **Joern install** — see Phase 3 above. Trigger with the install
   one-liner; the engine wiring picks it up automatically.
2. **JS PoC support in validator** — `_run_poc` only knows Python today.
3. **Storage taint round 2** — generate CodeQL extension YAML from
   `storage_writes` and re-run hybrid scan. Big recall win for stored
   XSS / second-order injection.
4. **Visualization upgrade path** — if the Graphviz output gets unwieldy,
   the same DuckDB shape can drive React Flow without changing the data
   model.
5. **Taxonomy maintenance** — `bug_classes.yaml` carries the Phase 1 set;
   regular review against your active bug-bounty programs lets you trim
   noise (e.g. drop `prompt-injection` if you don't audit LLM apps, or
   add custom categories).
6. **Caching strategy for repeat scans** — current resumability is per-step
   and snapshot-pinned by commit. Cross-run incremental analysis (only
   re-scan files changed since last commit) is sketched in spec §10 but
   not implemented; could halve cost on repeat scans of active repos.
7. **Skill auto-update** — `install-skills` overwrites `~/.claude/skills/*`
   on each run. If you customise the prompts post-install, those edits get
   clobbered. Consider an `--no-overwrite` flag or a hash-check.

## How to use this document

- Anything under "manually flagged" is what you specifically asked about.
- Anything under "engineering tradeoffs" is something I'd raise in a normal
  PR review.
- "Decisions still open" lists the next slate of changes worth your input.
- Every entry references the relevant code or spec section so you can
  jump to the source.

If you want me to act on any item, just point at it and say "do this".
