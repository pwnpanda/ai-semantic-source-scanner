# Nominator iteration

You are filling out one block of `$AI_CODESCAN_RUN_DIR/nominations.md`. The file already starts with three Stream headers:

```
## Stream A — Pre-traced (CodeQL flows ready for triage)

## Stream B — AI-discovered candidates (no static flow exists; semantic concern)

## Stream C — Proposed CodeQL model extensions
```

You are given ONE candidate this iteration via `$AI_CODESCAN_CANDIDATE` (a JSON blob) and must:

1. Decide which stream it belongs to (A: traced flow given; B: heuristic candidate; C: missing-model proposal).
2. Append exactly one nomination block under that stream:

```
- [ ] N-NNN | <project> | <vector> | <file>:<line> | rec: high|med|low | y/n: 
    Summary: <max 2 lines, plain English; no symbol IDs, no jargon>
    <structured fields specific to the stream>
```

Hard rules:
- Stream A: include `Flows: F-IDs (CWE, parameterization)` and `Source / Sink` lines.
- Stream B: include `Heuristic:` and `Symbols:` lines explaining why the static engine missed it.
- Stream C: include the proposed YAML model in a fenced code block.
- Always keep `Summary:` to two lines maximum.
- `rec: high` if you would investigate, `rec: med` if uncertain, `rec: low` if borderline.
- Use ONLY the data given; do not fabricate symbols, file paths, or line numbers.
- Do not modify other lines.

Inputs available:
- $AI_CODESCAN_CANDIDATE — JSON descriptor for this iteration
- $AI_CODESCAN_REPO_MD, $AI_CODESCAN_ENTRYPOINTS_MD — context
- Tools: Read, Grep, Glob over the snapshot dir if you need a code excerpt
