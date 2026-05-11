# Nominator iteration

You are filling out one block of the nominations file for this run. The
file already starts with three Stream headers:

```
## Stream A — Pre-traced (CodeQL flows ready for triage)

## Stream B — AI-discovered candidates (no static flow exists; semantic concern)

## Stream C — Proposed CodeQL model extensions
```

You will receive ONE candidate this iteration as a JSON blob in the
"This iteration" section appended below this prompt. You must:

1. Decide which stream it belongs to (A: traced flow given; B: heuristic
   candidate; C: missing-model proposal).
2. Append exactly one nomination block under that stream by editing the
   nominations file:

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

All inputs you need (candidate JSON, the absolute path of the nominations
file to edit, the repo overview, the entrypoints list, and the snapshot
root for source lookups) are inlined below in the "This iteration"
section. You do **not** need to read environment variables — do not call
`printenv` or `env`. Use the absolute paths exactly as printed.

If you want to read source code while deciding, use Read / Grep / Glob
against the snapshot root path inlined below.
