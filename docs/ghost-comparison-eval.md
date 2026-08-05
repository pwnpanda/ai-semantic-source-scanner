# Ghost Comparison Eval

## Purpose

Compare Ghost's AI-native SAST workflow with `ai-codescan` on a target with known ground truth.

Recommended target:

```bash
eval-targets/aspnet-minimal-sqli
```

Ground truth:

| Target | CWE | Expected finding |
| --- | --- | --- |
| `eval-targets/aspnet-minimal-sqli/Program.cs` | CWE-89 | route parameter `id` flows into concatenated SQL executed by `SqliteCommand.ExecuteReader()` |

## Why This Target

This target exercises a scanner difference introduced in this repo:

- Ghost scans through repository context, grep-based file nomination, and LLM analysis.
- `ai-codescan` adds deterministic project detection, CodeQL/Semgrep/Joern flow ingestion, dedupe, and optional LLM stages.
- The Joern layer now treats C# minimal API lambda parameters as request sources. Without that modeling, `id` is easy to miss because it does not appear as `Request.Query`, `Request.RouteValues`, or another explicit request-field read.

This is a good delta target because a single file has a known source, sink, and clean route. It is small enough to audit manually while still requiring framework-aware source modeling.

## Run `ai-codescan`

Default whole-scanner check:

```bash
.venv/bin/python -m ai_codescan --cache-dir /tmp/aics-ghost-eval-cache \
  eval run --targets eval-targets --out /tmp/aics-ghost-eval-output
```

Expected summary: `pass=1`.

The eval command runs the scanner's hybrid path and scores the final
`index.duckdb` flows against the manifest ground truth. Use this for
whole-scanner comparisons.

Engine-specific Joern regression check:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
from ai_codescan.engines import joern

target = Path("eval-targets/aspnet-minimal-sqli")
jsonl = joern.run_joern(target, cache_dir=Path("/tmp/aics-ghost-eval"), project_id="aspnet-minimal-sqli", language="csharp")
for flow in joern.parse_flows(jsonl):
    print(flow)
PY
```

Expected: exactly one flow, with `cwe='CWE-89'`, a source at the route-bound `id` parameter, and `sink_name='ExecuteReader'`.

Manual prep path:

```bash
.venv/bin/python -m ai_codescan prep eval-targets/aspnet-minimal-sqli --engine hybrid --cache-dir /tmp/aics-ghost-eval-cache
```

Then query the generated DuckDB `flows` table for `CWE-89`.

## Run Ghost

Run Ghost from the target directory so its repo context is scoped to this eval target:

```bash
cd eval-targets/aspnet-minimal-sqli
/ghost-repo-context
/ghost-scan-code balanced
```

Expected finding: one SQL injection in `Program.cs`.

Evaluation rule:

- Pass: scanner reports `Program.cs`, CWE-89/SQL injection, source `id`, sink `ExecuteReader` or the SQL command execution.
- Partial: scanner reports SQL injection but misses source/sink precision.
- Miss: scanner produces no SQL injection finding.
- False positive: scanner reports `/health` or another non-vulnerable path.

## Relative Effectiveness Hypothesis

Expected strengths for `ai-codescan`:

- Higher recall on framework-specific source shapes once modeled, because Joern/CodeQL/Semgrep can surface flows before the LLM stage.
- Better repeatability: the same target produces a machine-readable flow record.
- Better auditability: source and sink line numbers are stored in JSONL/DuckDB.

Expected strengths for Ghost:

- Lower setup cost.
- Stronger exploratory reasoning on business logic and authorization flaws that are not already encoded as static-analysis source/sink patterns.
- Better fit for manual, interactive audits where the user can steer scope.

Expected weakness for Ghost on this target:

- It depends on nomination plus LLM recognition of implicit ASP.NET Core route binding. If the scan plan or nomination does not prioritize C# minimal API SQL sinks, it can miss the issue even though the file is small.

Expected weakness for `ai-codescan`:

- It only wins this target because the C# source model now includes minimal API lambda parameters. Before that addition, the Joern check missed this exact shape.
