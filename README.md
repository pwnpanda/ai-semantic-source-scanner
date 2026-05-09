# ai-semantic-source-scanner (`ai-codescan`)

AI-driven SAST pipeline for JavaScript / TypeScript / Python / HTML codebases. Combines deterministic static analysis (AST, SCIP, CodeQL, Semgrep, optional Joern) with LLM agents that nominate bug candidates, write per-finding reports, and validate exploits in a hardened Docker sandbox.

Five-stage pipeline with human-in-the-loop gates between every stage. Swappable LLM provider (`claude`, `gemini`, or `codex`).

```
prep ─→ Gate 1 ─→ analyze ─→ Gate 2 ─→ validate ─→ Gate 3 ─→ report
```

---

## What it does

- **`prep`** — snapshots the target, runs ts-morph + parse5 + tree-sitter for AST, builds a SCIP cross-reference index, runs CodeQL (and optionally Semgrep / Joern), ingests every flow into a per-target DuckDB.
- **`nominate`** — wide-pass LLM proposes candidate bugs in three streams (CodeQL-traced, AI-discovered, model-extension proposals) with a one-line plain-English summary per item.
- **`gate-1` / `-2` / `-3`** — open the queue file in `$EDITOR`, mark `y/n:` per item, or `--yes` to accept all.
- **`analyze`** — per-finding sub-agent reads a minimal flow slice, walks evidence, writes `findings/<id>.md`.
- **`validate`** — per-finding PoC writer + sandboxed Docker runner; flips status to `verified` / `rejected` / `poc_inconclusive`.
- **`report`** — renders verified findings as bug-bounty-ready markdown with CWE→severity inference.
- **`visualize`** — Graphviz DOT/SVG/PNG of flows.

---

## Requirements

| Required | Why |
|---|---|
| **`uv`** | Python 3.13 venv + dep manager |
| **`node`** ≥ 22 + **`pnpm`** | AST worker (ts-morph + parse5 + tree-sitter) |
| **`git`** | Snapshots use `git worktree` for git targets |

| Optional | What you lose without it |
|---|---|
| **`codeql`** CLI 2.25+ | The default static engine. Without it, `--engine llm-heavy` works as a fallback |
| **`scip-typescript`** | SCIP cross-reference symbol IDs (`npm i -g @sourcegraph/scip-typescript`) |
| **`docker`** | `validate` PoC sandbox. Falls back to local execution with `--no-sandbox` |
| **`dot`** (graphviz) | `visualize --fmt svg|png` (`dot` output still works) |
| **`claude` / `gemini` / `codex`** | Pick whichever LLM CLI you want; at least one must be on PATH |
| **Joern** | Adds a third engine to `--engine hybrid` (deferred — see Install) |
| **Semgrep** | Auto-installed via `uv sync` (no separate install) |

---

## Install

The installer is interactive. It will:

1. Verify required tools are present.
2. Set up the Python venv (`uv venv`, `uv sync --all-groups`).
3. Install Node worker deps (`pnpm install` inside `ai_codescan/ast/node_worker/`).
4. Report which optional integrations are present / missing.
5. **Prompt explicitly about installing Joern (~1.5 GB)** — defaults to "no".
6. Optionally copy bundled Claude Code skills into `~/.claude/skills/`.
7. Run the test suite to verify.

```bash
git clone git@github.com:pwnpanda/ai-semantic-source-scanner.git
cd ai-semantic-source-scanner
bash scripts/install.sh
```

**Non-interactive install** (CI, dotfile bootstrap):

```bash
AICS_NONINTERACTIVE=1 AICS_INSTALL_JOERN=no bash scripts/install.sh
# or to force-install Joern without prompting:
AICS_NONINTERACTIVE=1 AICS_INSTALL_JOERN=yes bash scripts/install.sh
```

After install, the binary is available as `uv run ai-codescan` (or activate the venv with `source .venv/bin/activate` and use `ai-codescan` directly).

---

## Quick start

```bash
# Clone a target (for a real scan use a real target)
git clone --depth 1 https://github.com/expressjs/express /tmp/express

# End-to-end Phase 1: prep + nominate + gate-1 with auto-accept
uv run ai-codescan run /tmp/express --target-bug-class injection --yes

# Continue through Phase 2: deep analysis → validate → report
uv run ai-codescan analyze
uv run ai-codescan gate-2 --yes
uv run ai-codescan validate
uv run ai-codescan gate-3 --yes
uv run ai-codescan report --report-dir ./report
```

### Python target example

The same workflow drives Python projects — language is auto-detected from
`pyproject.toml` / `setup.py` / `setup.cfg` / `requirements.txt`. Running
`prep` on a Flask/FastAPI/Django service routes it through CodeQL Python
(`python-security-extended.qls`), Semgrep (`--config=auto`), Joern's
`pysrc2cpg` frontend, and tree-sitter-python AST extraction. Optional
SCIP indexing via `scip-python` (`npm i -g @sourcegraph/scip-python`) adds
cross-file symbol resolution.

```bash
uv run ai-codescan prep ./tests/fixtures/tiny-flask --engine hybrid
uv run ai-codescan run ./tests/fixtures/tiny-flask --target-bug-class injection --yes
```

Reports land in `./report/YYYY-MM-DD--<severity>--<vuln-class>--<component>.md`.

---

## Common commands

```bash
# Discovery + filtering
uv run ai-codescan list-bug-classes
uv run ai-codescan prep <target> --target-bug-class xss,sqli,idor

# Pick a different LLM provider per gate
uv run ai-codescan run <target> --llm-provider gemini --llm-model gemini-2.5-pro --yes
uv run ai-codescan analyze        --llm-provider codex  --llm-model o3
uv run ai-codescan validate       --llm-provider claude --llm-model opus

# Inspect the project DB
uv run ai-codescan query "SELECT cwe, COUNT(*) FROM flows GROUP BY cwe"
uv run ai-codescan flows --from <symbol-id>
uv run ai-codescan view  --file /path/in/snapshot.ts
uv run ai-codescan entrypoints

# Engine alternatives
uv run ai-codescan prep <target> --engine codeql       # default
uv run ai-codescan prep <target> --engine llm-heavy    # LLM walks flows; no CodeQL needed
uv run ai-codescan prep <target> --engine hybrid       # CodeQL + Semgrep + Joern (when on PATH), deduped

# Layer 5 — stored / async second-order taint
uv run ai-codescan taint-schema --run                  # populate storage_locations + writes
uv run ai-codescan taint-schema --show
uv run ai-codescan taint-schema --edit                 # hand-edit annotations

# Visualization
uv run ai-codescan visualize --fmt svg --cwe CWE-89 --out flows.svg
uv run ai-codescan visualize --fmt png --limit 50 --out flows.png

# Cache management
uv run ai-codescan cache list
uv run ai-codescan cache rm <repo-id>
```

---

## Configuration

| Flag | Default | Notes |
|---|---|---|
| `--engine {codeql,llm-heavy,hybrid}` | `codeql` | Pick the static analysis backbone |
| `--target-bug-class <list>` | all | Comma-separated; e.g. `injection,xss,idor` or `@injection` |
| `--llm-provider {claude,gemini,codex}` | `claude` | LLM CLI to drive each phase |
| `--llm-model <name>` | provider default | e.g. `opus`, `gemini-2.5-pro`, `o3` |
| `--temperature <float>` | `0.0` | Determinism by default |
| `--report-dir <path>` | `./report/` | Where final reports land |
| `--cache-dir <path>` | `~/.ai_codescan/repos/<id>/` | Per-target snapshot + DuckDB |
| `--commit <sha>` | `HEAD` | Pin git snapshot to a commit |
| `--yes` | off | Skip interactive HITL gates |
| `--cost-cap <usd>` | none | Abort phase when LLM spend exceeds this |
| `--no-sandbox` | off | `validate` runs PoC locally instead of in Docker |

LLM provider/model + temperature are persisted to `runs/<run_id>/run.json` for auditability.

---

## Joern (deferred install)

`--engine hybrid` is wired to use Joern in addition to CodeQL and Semgrep. The installer asks before downloading because of the size:

- **Download:** ~1.5 GB (JVM + Joern distribution)
- **Disk:** ~2 GB unpacked
- **Adds:** broader cross-file taint coverage on JS/TS, Java, Python, Go, Kotlin
- **Without it:** hybrid still runs CodeQL + Semgrep and dedupes; you only lose the third opinion

Install later if you skipped initially:

```bash
AICS_INSTALL_JOERN=yes bash scripts/install.sh
```

---

## Project layout

```
ai_codescan/                         # Python package
├── snapshot.py                      # Read-only snapshot via git worktree or cp
├── stack_detect.py                  # Detect projects + frameworks + package manager
├── ast/                             # Node worker + Python wrapper
├── index/                           # SCIP indexer + DuckDB schema/ingestion
├── engines/                         # codeql, semgrep, joern (stub), hybrid, llm_heavy
├── ingest/sarif.py                  # Parse SARIF into flows
├── findings/                        # Finding model + queue
├── analyzer.py / nominator.py / validator.py
├── report.py / visualize.py / sandbox.py
├── runs/state.py                    # Cost ledger + run state
├── llm.py                           # Swappable provider abstraction
├── taxonomy/bug_classes.yaml        # 35 bug classes with CWE/CodeQL mappings
└── skills/                          # Bundled Claude Code skills
    ├── wide_nominator/
    ├── deep_analyzer/
    ├── validator/
    └── llm_heavy/

docs/superpowers/
├── specs/                           # Phase 1 + 2 design specs
└── plans/                           # Per-sub-plan implementation plans

tests/                               # 158 tests, ~2 min full suite
TRADEOFFS.md                         # Autonomous decisions + open follow-ups
```

---

## Development

```bash
make check          # ruff + ty + pytest
make lint           # ruff check
make format         # ruff format
make typecheck      # ty check --error-on-warning
make test           # pytest
```

Quality gates: zero ruff warnings, zero ty errors, all tests green. ~158 tests, ~2 min.

---

## Pointers

- **Tradeoffs and open questions:** [TRADEOFFS.md](TRADEOFFS.md)
- **Phase 1 design:** [`docs/superpowers/specs/2026-05-08-ai-codescan-phase1-design.md`](docs/superpowers/specs/2026-05-08-ai-codescan-phase1-design.md)
- **Phase 2 design:** [`docs/superpowers/specs/2026-05-09-ai-codescan-phase2-design.md`](docs/superpowers/specs/2026-05-09-ai-codescan-phase2-design.md)
- **Per-sub-plan implementation plans:** `docs/superpowers/plans/`
- **Milestone tags:** `git tag -l` lists 14 (`phase-1a` through `phase-3`).

---

## Status

Phases 1, 2, and 3 are complete and tagged. JavaScript / TypeScript and Python are fully implemented (every layer of the pipeline — stack detection, CodeQL, Semgrep, Joern, AST extraction, SCIP indexing, storage-taint regexes, framework-aware entrypoint detection, fixtures, end-to-end smoke tests). Joern install remains opt-in. Java / Go / Ruby are next on the roadmap. See [TRADEOFFS.md](TRADEOFFS.md) for the full list of autonomous decisions.

## Claude Sessions

| Session | Summary | Date |
|---------|---------|------|
| `python-language-support` | Added full-parity Python language support: stack_detect (pyproject/setup/requirements + framework + pkg-mgr detection), CodeQL Python query suite, Joern pysrc2cpg + Python source/sink patterns, tree-sitter-python AST worker, Python idiom regexes in storage_taint, tiny-flask fixture, end-to-end smoke test. | 2026-05-09 |
| `js-python-elevation` | Elevated JS/TS and Python from MVP to fully implemented: language-aware views.py (Python `#` comments), broader JS entrypoints (NestJS decorators, Next.js Pages/App Router, Remix loaders/actions), Python entrypoints (Flask/FastAPI/Django/Starlette + Celery/argparse), tightened Joern JS XSS receiver filter, optional scip-python integration, tiny-fastapi CWE-22 fixture, hybrid-mode integration test, README Python quickstart. | 2026-05-09 |
