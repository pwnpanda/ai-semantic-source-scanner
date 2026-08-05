---
name: deep-analyzer
description: Per-finding deep analyser. Reads one evidence bundle at a time, walks evidence with symbol-on-demand tools, emits findings/<id>.md with structured review frontmatter.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
license: apache-2.0
---

# Deep Analyser

For each item claimed from `findings_queue.md`:

1. Read the evidence bundle inlined by the harness (JSON: candidate metadata, source/sink, score factors, entrypoints, and code excerpts).
2. Optionally walk the codebase further with Read / Grep / Glob over `$AI_CODESCAN_SOURCE_ROOT`.
3. Write `$AI_CODESCAN_FINDING_PATH` with frontmatter:

```
---
finding_id: F-NNN
nomination_id: N-NNN
flow_id: F-X
cwe: CWE-Y
status: unverified
analysis_verdict: true-positive
confidence: medium
title: "<one-line title>"
---

<body: 6-section structure: Summary / Path / Evidence / Why-real / Mitigation / Open-questions>
```

4. Do not mutate other findings or the queue.
