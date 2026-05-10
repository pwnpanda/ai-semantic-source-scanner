# Quality and coverage summary

This document records the elevation arc since the original Phase 1–3
build: language coverage broadened from JS/TS-only to twelve targets,
quality gates lifted from ad-hoc local checks to CI + pre-commit + types
+ property tests. The goal of this doc is durability — anyone returning
to the project should be able to read this once and understand the
shape of the test suite, what's gated on which tooling, and what's
outstanding.

## At a glance

| Axis | Before | After |
|---|---|---|
| Source-code languages | JS / TS | JS / TS / Python / Java / Kotlin / Go / Ruby / PHP / C# / Bash |
| Config-as-target | — | YAML (GitHub Actions / k8s / Helm / docker-compose), HTML |
| Bare-source detection | — | `.py` / `.java` / `.go` / `.rb` / `.php` / `.cs` / `.sh` (project-less repos surface as a kind-typed Project) |
| Project kinds | NODE / HTML_ONLY | NODE / PYTHON / JAVA / GO / RUBY / PHP / CSHARP / BASH / YAML / HTML_ONLY |
| Unit tests | ~199 | 343 (integration excluded) |
| Integration tests | 2 (CodeQL JS) | 14 (4 CodeQL + 7 Joern + 3 SCIP) |
| Total tests collected | ~201 | ~383 |
| Line coverage | unmeasured | 76.3 % (floor pinned at 75 % in CI) |
| Lint | ruff (project-only) | ruff + pre-commit hook + CI gate |
| Types | ty (default rules) | ty with 9 strictness lifts (`error`-level) |
| CI | none | GitHub Actions: ruff + ty + pytest + coverage floor |
| Pre-commit | none | prek with ruff + ty (CI parity) |
| Property-based tests | none | hypothesis on storage_taint parsers (caught one real bug) |
| Storage-taint LLM resolver | JS-only prompt | per-language prompt examples + `taint-schema --init` from bundled example |

## Languages and pipeline coverage

| Language | stack_detect | CodeQL | Semgrep | Joern | tree-sitter AST | SCIP | Storage-taint | Entrypoints | Fixture |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|---|
| JavaScript / TypeScript | ✅ | ✅ | ✅ | `javascript` | TS grammar | scip-typescript | ✅ | Express / Fastify / Nest / Next / Remix | tiny-vuln, tiny-express, tiny-react, monorepo-pnpm |
| Python | ✅ | ✅ | ✅ | `pythonsrc` | tree-sitter-python | scip-python (opt-in) | ✅ | Flask / FastAPI / Django / Starlette / Celery | tiny-flask, tiny-fastapi |
| Java | ✅ | ✅ `--build-mode=none` | ✅ | `JAVASRC` | tree-sitter-java | scip-java | ✅ | Spring / JAX-RS / Kafka / Scheduled | tiny-spring |
| Kotlin (JVM-shared) | via `JAVA` kind | ✅ `java-kotlin` extractor | ✅ | `KOTLIN` (file-mix heuristic) | tree-sitter-kotlin | scip-java (semanticdb) | ✅ Exposed | Ktor + Spring-on-Kotlin | tiny-ktor |
| Go | ✅ | ✅ (autobuild) | ✅ | `GOLANG` | tree-sitter-go | scip-go | ✅ database/sql / sqlx / go-redis | net/http, Gin, Echo, Chi, Fiber | tiny-gin |
| Ruby | ✅ | ✅ | ✅ | `RUBYSRC` (beta — thin CPGs) | tree-sitter-ruby | — | ✅ ActiveRecord / Mysql2 / PG / SQLite3 | Rails / Sinatra / Sidekiq | tiny-sinatra |
| PHP | ✅ | ❌ no official support | ✅ | `PHP` (needs `php` on PATH) | tree-sitter-php | — | ✅ PDO / mysqli / wpdb | Laravel / Symfony / Slim / WordPress / WP-CLI | tiny-slim |
| C# / .NET | ✅ | ✅ `--build-mode=none` (CLI 2.18.4+) | ✅ | `CSHARPSRC` | tree-sitter-c-sharp | — | ✅ ADO.NET / Dapper / EF Core | ASP.NET attribute routing / minimal APIs / Azure Functions | tiny-aspnet |
| Bash | ✅ | ❌ no support | ✅ | ❌ no Joern frontend | tree-sitter-bash | — | — | `getopts` / `eval` / `source` / `bash -c` | tiny-bash |
| YAML / GitHub Actions | ✅ | ❌ no support | ✅ | ❌ no Joern frontend | @tree-sitter-grammars/tree-sitter-yaml | — | — | `on:` triggers, `${{ github.event.* }}` interpolations | tiny-actions |

Detection precedence is manifest > bare-source > HTML-only fallback. A
polyglot repo (Node frontend + Python backend at root) keeps its
manifest-detected projects; bare-source detection only fires when no
manifest project covers the root.

## Test inventory

```
tests/
├── conftest.py
├── test_analyzer.py                 # nominator → analyzer flow
├── test_ast_runner.py               # node worker dispatch
├── test_cli.py                      # all CLI subcommands incl. taint-schema --init
├── test_codeql_runner.py            # 4 unit + 4 gated integration (Java/Go/Ruby/C#)
├── test_config.py
├── test_engines_hybrid.py           # consensus boost + per-language Joern routing
├── test_engines_llm_heavy.py
├── test_entrypoints_detect.py       # 40+ framework regex cases across 9 langs
├── test_entrypoints_render.py
├── test_findings_model.py
├── test_findings_queue.py
├── test_gate.py
├── test_index_duckdb.py
├── test_index_scip.py               # +Java/Go skip-when-CLI-missing cases
├── test_joern_runner.py             # 1 unit + 7 gated integration
├── test_llm.py
├── test_manifest.py
├── test_nominator_orchestrator.py
├── test_prep_python.py / java / go / ruby / php / csharp / kotlin / bash / yaml
├── test_repo_md.py
├── test_report.py
├── test_runs_state.py
├── test_sandbox.py                  # +9 multi-language profile tests
├── test_sarif_ingest.py
├── test_server.py
├── test_sidecars.py
├── test_slice.py
├── test_snapshot.py
├── test_stack_detect.py             # 47 cases, every supported language
├── test_storage_taint.py            # 37 unit cases
├── test_storage_taint_properties.py # 13 hypothesis-driven cases
├── test_taxonomy_diff.py
├── test_taxonomy_loader.py
├── test_user_config.py
├── test_validator.py                # +5 multi-language sandbox routing
├── test_views.py
└── test_visualize.py
```

### Integration test gating

All integration tests are marked `@pytest.mark.integration` and skipped
in CI (`pytest -m "not integration"`). They run locally when the host
has the matching toolchain:

| File | Tests | Required tooling |
|---|---|---|
| `test_codeql_runner.py` | 6 (1 JS + 4 fixtures + 1 missing-pack helper) | `codeql` CLI; auto-fetches the language pack via `codeql pack download` (timeout + retry) |
| `test_codeql_runner.py` (Go-specific) | included in 4 fixtures | additionally requires `go` toolchain on PATH |
| `test_joern_runner.py` | 7 (one per fixture) | `joern` + `joern-parse`; PHP test additionally requires `php` |
| `test_index_scip.py` | 2 (TS + Python) | `scip-typescript` / `scip-python`; falls through cleanly when missing |

End-to-end smoke tests on each fixture (`test_prep_<lang>.py`) run
without integration tooling — they exercise stack detection, AST
extraction, and DuckDB ingestion, and are not gated.

### Property-based tests

`tests/test_storage_taint_properties.py` exercises four parsers under
generated input via Hypothesis:

- `detect_sql_storage_ids` — never raises on arbitrary text; lower-cases
  output canonically.
- `classify_sql_op` — returns one of `{"read", "write", None}`.
- `classify_call` — returns a tuple of known kinds + ops, or None.
- `_key_pattern_to_regex` — matches its own literal storage_id; `*` holes
  match arbitrary runtime values.

The Hypothesis tests caught one real bug on first run:
`sqlglot.errors.TokenError` (raised on inputs like a bare `"`) wasn't
handled, only `ParseError` was. Fixed in `storage_taint.py` to catch both.

## Quality gates

### Coverage floor

`pytest --cov-fail-under=75` is enforced both locally and in CI. Current
coverage is 76.3 %. Gaps are concentrated in real-CLI / LLM integration
paths that are appropriately covered by the gated integration tests:

- `engines/joern.py` — 42 % (most lines exercised by the gated Joern
  integration tests)
- `engines/semgrep.py` — 47 % (Semgrep CLI integration)
- `engines/llm_heavy.py` — 66 % (LLM round-trip)
- `validator.py` — 61 % (Docker sandbox; per-language profile dispatch
  table is unit-tested via mocks)
- `index/scip.py` — 69 % (real-CLI paths for scip-typescript / python /
  java / go)

Generated `ai_codescan/third_party/scip_pb2.py` is excluded from both
ruff and ty.

### Lint and types

```toml
[tool.ruff]
line-length = 100
target-version = "py313"
extend-exclude = ["ai_codescan/third_party"]

[tool.ty.environment]
root = ["ai_codescan", "tests"]

[tool.ty.rules]
unresolved-import = "error"
unresolved-attribute = "error"
unresolved-reference = "error"
invalid-assignment = "error"
invalid-return-type = "error"
missing-argument = "error"
too-many-positional-arguments = "error"
unknown-argument = "error"
invalid-argument-type = "error"
invalid-parameter-default = "error"
```

These nine ty escalations turn signal that's typically warn-level into
hard fails. `ty check ai_codescan/` is currently clean.

### CI workflow

`.github/workflows/test.yml` runs on every push and PR to `main`:

1. `ruff check ai_codescan/ tests/`
2. `ruff format --check ai_codescan/ tests/`
3. `ty check ai_codescan/`
4. `pytest tests/ -m "not integration" --cov-fail-under=75`

Concurrency is per-ref with PR cancellation. Actions are pinned to full
SHAs with version-tag comments per the global standards.

### Pre-commit hooks

`.pre-commit-config.yaml` runs the same `ruff check` / `ruff format` /
`ty check` trio locally on every commit via [prek](https://github.com/j178/prek)
(or the original `pre-commit`). Generated protobuf code is excluded.

### Validator multi-language sandbox

PoC scripts dispatch to per-language Docker images by file extension:

| Ext | Image | Run command |
|---|---|---|
| `.py` (legacy) | `python:3.13-slim` | `python /poc/poc.py` |
| `.js` / `.mjs` | `node:22-alpine` | `node /poc/poc.js` |
| `.ts` | `node:22-alpine` | `npx --yes tsx /poc/poc.ts` |
| `.java` | `openjdk:21-slim` | `java /poc/poc.java` (single-file mode, JEP 330) |
| `.go` | `golang:1.22-alpine` | `go run /poc/poc.go` |
| `.rb` | `ruby:3.3-alpine` | `ruby /poc/poc.rb` |
| `.php` | `php:8.3-cli-alpine` | `php /poc/poc.php` |
| `.sh` / `.bash` | `bash:5` | `bash /poc/poc.sh` |
| `.cs` | deferred — file-based `dotnet run` needs .NET 10+ |

`--no-sandbox` mode rejects non-Python with a clear `SandboxUnavailableError`.

## Outstanding work

- **#105 — pipeline TODO**: multi-language monorepo end-to-end test on a
  real polyglot repo. Waiting on a target repo from the user.
- **Coverage of validator + scip** could lift via Docker-aware integration
  tests; deferred until a real CI runner with Docker and the SCIP CLIs is
  set up.
- **Joern Ruby (`rubysrc2cpg`)** is documented as beta — produces thin
  CPGs on DSL-heavy code. Upstream maturity will close this gap.
- **PHP CodeQL** isn't on GitHub's roadmap; Semgrep + Joern's `php2cpg`
  cover the gap.

## Commit trail

The arc spans these commits on `main`:

```
… add language support, polish, and quality lifts:
6096685 feat(engine): hybrid mode runs CodeQL + Semgrep (+ Joern when available)
2f36567 docs: phase 2 + 3 status with end-to-end usage
711b985 feat(engine): consume LLM keys, multi-engine consensus, joern reachableByFlows
a5be6b5 feat(language): full-parity Python support
e5a470a feat(language): elevate JS/TS and Python from MVP to fully implemented
71df580 feat(language): Java MVP+ support across full pipeline
32d09e3 feat(language): Go MVP+ support across full pipeline
858435d feat(language): Ruby MVP+ support across full pipeline
6ac7371 feat(language): PHP MVP+ support + bare-source language detection
ef932b1 feat(language): C#/.NET MVP+ support across full pipeline
1dfceab test(codeql): real-CodeQL integration tests for Java/Go/Ruby/C#
e665fdc feat(language): Kotlin support (Ktor + Spring-on-Kotlin)
3f7c342 feat(language): Bash / shell-script support
3bbabea feat(language): YAML / GitHub Actions support
7cc1827 feat(taint): pre-seeded schema.taint.yml + per-language resolver examples
a95f7aa feat(engines): CodeQL pack auto-fetch hardening, SCIP Java+Go, Joern Kotlin
d07aab5 Merge worktree: Joern integration tests
5d00c08 docs: README session row for engines polish + validator multi-language
… (this commit) feat(quality): CI + pre-commit + property tests + stricter ty
```
