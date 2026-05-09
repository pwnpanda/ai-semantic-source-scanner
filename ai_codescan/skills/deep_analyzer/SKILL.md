---
name: deep-analyzer
description: Per-finding deep analyser. Reads one slice at a time, walks evidence with symbol-on-demand tools, emits findings/<id>.md with status=unverified.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
license: apache-2.0
---

# Deep Analyser

For each item claimed from `findings_queue.md`:

1. Read the slice from `$AI_CODESCAN_SLICE_FILE` (JSON: source loc, sink class, ±5-line excerpts at each step).
2. Optionally walk the codebase further with Read / Grep / Glob over `$AI_CODESCAN_SOURCE_ROOT`.
3. Write `$AI_CODESCAN_FINDING_PATH` with frontmatter:

```
---
finding_id: F-NNN
nomination_id: N-NNN
flow_id: F-X
cwe: CWE-Y
status: unverified
title: "<one-line title>"
---

<body: 6-section structure: Summary / Path / Evidence / Why-real / Mitigation / Open-questions>
```

4. Do not mutate other findings or the queue.
