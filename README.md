# ai-codescan

AI-driven SAST pipeline. Phase 1 = deterministic prep + wide-pass nominator with HITL gate.

See `docs/superpowers/specs/2026-05-08-ai-codescan-phase1-design.md` for the full design.

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
