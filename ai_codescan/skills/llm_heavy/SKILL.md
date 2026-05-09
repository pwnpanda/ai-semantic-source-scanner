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
