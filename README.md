# ai-semantic-source-scanner (`ai-codescan`)

AI-driven SAST pipeline. Phase 1 = deterministic prep + wide-pass nominator with HITL gate.

See `docs/superpowers/specs/2026-05-08-ai-codescan-phase1-design.md` for the full design and `docs/superpowers/plans/` for the per-phase implementation plans.

## Install (development)

```bash
uv venv
uv sync --all-groups
uv run ai-codescan --help
```

## Phase 1A status

This sub-plan delivers: `ai-codescan prep <target>` produces a snapshot and `repo.md`.

## Smoke test (Phase 1A)

```bash
git clone --depth 1 https://github.com/expressjs/express.git /tmp/tmp-express
uv run ai-codescan prep /tmp/tmp-express
cat ~/.ai_codescan/repos/tmp-express-*/repo.md
uv run ai-codescan cache list
```

## Phase 1B status

`prep` now also runs the AST extractor (ts-morph + parse5 + tree-sitter), builds a SCIP index, and populates `index.duckdb`. New subcommands: `query`, `flows --from/--to`. External tools required:

- `node` (>=22) and `pnpm` for the AST worker
- `scip-typescript` global install:

```bash
npm i -g @sourcegraph/scip-typescript
```

Quick check after running prep:

```bash
ai-codescan query "SELECT kind, COUNT(*) FROM symbols GROUP BY kind"
ai-codescan flows --from <symbol-id>
```

## Phase 1C status

`prep` now runs CodeQL after AST/SCIP. Install CodeQL CLI 2.25+ and ensure `codeql` is on PATH. Filter scan classes via `--target-bug-class injection` or `--target-bug-class xss,sqli`.

```bash
ai-codescan prep /path/to/target --target-bug-class injection
ai-codescan list-bug-classes
ai-codescan query "SELECT cwe, COUNT(*) FROM flows GROUP BY cwe"
```

## Phase 1D status

`prep` now derives `entrypoints.md`, emits per-file `*.enrich.jsonl` sidecars, and offers `view`/`entrypoints` subcommands.

```bash
ai-codescan entrypoints
ai-codescan view --file /path/to/source/file.ts
```

## Phase 1E status — Phase 1 complete

End-to-end pipeline: `ai-codescan run <target>` chains prep → nominate → gate-1. Use `--yes` to skip the editor.

```bash
ai-codescan install-skills
ai-codescan run /path/to/target --target-bug-class injection,idor --yes
```

Phase 1 deliverables:
- Snapshot (git worktree or cp), stack detect, AST extraction (ts-morph + parse5 + tree-sitter), SCIP indexing, CodeQL DB build + analyze, SARIF flow ingestion into DuckDB
- Per-file `*.enrich.jsonl` sidecars + `entrypoints.md` + `repo.md`
- `view`, `entrypoints`, `query`, `flows --from/--to` inspection commands
- Wide-nominator skill (Claude Code) with three-stream output and `y/n:` HITL gate
- Run-state JSON + cost ledger

### Swappable LLM provider

Pick the LLM CLI per scan. All three (`claude`, `gemini`, `codex`) must be installed and on PATH for whichever you use; defaults to `claude`.

```bash
ai-codescan run /path/to/target --llm-provider gemini --llm-model gemini-2.5-pro --yes
ai-codescan nominate --llm-provider codex --llm-model o3
```

The selection is persisted to `runs/<run_id>/run.json` for auditability and re-runs.

## Phase 2 status — deep analysis, validation, reports

Five-stage pipeline now runs end-to-end:

```bash
ai-codescan run /path/to/target --target-bug-class injection --yes  # phase 1
ai-codescan analyze                                                  # deep per-finding sub-agent
ai-codescan gate-2 --yes
ai-codescan validate                                                 # docker sandbox PoC
ai-codescan gate-3 --yes
ai-codescan report --report-dir ./report                             # bug-bounty-ready md
```

Layer 5 storage taint MVP runs separately:

```bash
ai-codescan taint-schema --run     # populate storage_locations + storage_writes
ai-codescan taint-schema --show    # inspect schema.taint.yml
ai-codescan taint-schema --edit    # hand-edit annotations
```

Alternative engine modes:

```bash
ai-codescan prep . --engine llm-heavy   # LLM walks flows itself (no CodeQL)
ai-codescan prep . --engine hybrid      # CodeQL + Semgrep (+ Joern when on PATH), deduped
```

## Phase 3 status — hybrid engine, visualization

```bash
ai-codescan visualize --fmt svg --cwe CWE-89 --out flows.svg
```

See [TRADEOFFS.md](TRADEOFFS.md) for autonomous decisions, open follow-ups, and how to opt into Joern integration (deferred install).
