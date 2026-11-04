---
name: llm-heavy
description: Walk a target repo's taint flows by reading source directly. Used when CodeQL coverage is poor for the target stack. Emits flows.jsonl that the orchestrator ingests into the same flows table.
allowed-tools: Read, Grep, Glob, Bash
license: apache-2.0
---

# LLM-heavy engine

You replace a static taint engine. Inputs:

- `$AI_CODESCAN_REPO_MD` — stack/framework context
- `$AI_CODESCAN_ENTRYPOINTS_MD` — every place user input enters the system
- `$AI_CODESCAN_SOURCE_ROOT` — read-only snapshot tree (use `Read` / `Grep` / `Glob`)
- `$AI_CODESCAN_OUT_PATH` — where to write `flows.jsonl`
- `$AI_CODESCAN_TARGET_BUG_CLASSES` — bug classes to focus on (comma-separated)

Job: trace each entrypoint's user-controlled inputs through the code until they reach a sink (or end safely). For every source→sink path, emit one JSON object on a line in `$AI_CODESCAN_OUT_PATH`:

```json
{
  "fid": "L-001",
  "tid": "T-001",
  "sid": "K-001",
  "cwe": "CWE-89",
  "engine": "llm-heavy",
  "confidence": "inferred",
  "source": {"file": "abs/path", "line": 13, "class": "http.body", "key": "name"},
  "sink":   {"file": "abs/path", "line": 42, "class": "sql.exec", "lib": "pg"},
  "steps":  [{"file": "abs/path", "line": 13}, {"file": "abs/path", "line": 42}]
}
```

Hard rules:

- Use ONLY data you can verify by reading source. No fabrication.
- One flow per line. Newline-delimited JSON.
- If you cannot find a credible flow, emit zero lines (do not invent one).
- Stop when you've covered every entrypoint, or when context is exhausted.

## Perl

Perl needs more care than the other stacks: no Joern frontend, no CodeQL pack
and no native Semgrep support parse it, so for `.pl` / `.pm` / `.psgi` / `.cgi`
files you are the *only* engine doing interprocedural reasoning. Nothing else
will catch what you miss here.

Sources — user input arrives as:

- `$cgi->param(...)`, `param(...)`, `$q->Vars`, `$q->multi_param`, `$q->cookie`
  (CGI.pm, still common in legacy code)
- `$c->param`, `$c->req->json`, `$c->req->body` (Mojolicious)
- `params->{x}`, `request->params`, `body_parameters` (Dancer/Dancer2)
- `$c->req->param` (Catalyst), `$env->{QUERY_STRING}` (raw PSGI)
- `%ENV`, `@ARGV`, and `STDIN` reads in CGI/cron scripts

Sinks — these Perl shapes are dangerous in ways that do not look like other
languages:

- **Two-argument `open`**: `open(FH, $path)` honours mode characters inside
  the *filename*, so a value starting with `|` executes a command and `>`
  truncates. The 3-arg form `open($fh, '<', $path)` is the safe one. A 2-arg
  open reached by user input is command injection, not just path traversal.
- **`system` / `exec` / backticks / `qx//`**: the single-argument form goes
  through the shell; the LIST form (`system($prog, @args)`) does not. Report
  only the string form.
- **String `eval("...")`** compiles its argument as Perl — RCE. Block
  `eval { ... }` is exception handling and is safe; do not confuse them.
- **DBI**: interpolation into `do` / `prepare` / `selectrow_array` /
  `selectall_arrayref` is SQL injection. `?` placeholders with bind values are
  safe — check whether the value is bound or interpolated.
- `Storable::thaw`, `YAML::Load`, and `Data::Dumper` + `eval` round-trips are
  unsafe deserialization.
- Taint mode (`#!/usr/bin/perl -T`) mitigates many of these; note it when
  present, but it only helps where values actually pass an untainting regex.
