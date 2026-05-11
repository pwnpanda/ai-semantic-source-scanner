# Nominator iteration

You are filling out one nomination block. You will receive ONE candidate
this iteration as a JSON blob in the "This iteration" section appended
to this prompt. You must:

1. Decide which stream it belongs to (A: traced flow given; B: heuristic
   candidate; C: missing-model proposal).
2. Print exactly one nomination block to stdout, between the sentinels
   shown below. The harness picks the block out of your output and
   appends it under the matching Stream header for you — you do **not**
   need filesystem write permission, and you must not call Edit, Write,
   or any other file-modifying tool.

## Output protocol — sentinel-bracketed block on stdout

Print exactly this on stdout, replacing the angle-bracket placeholders:

```
<<<AI_CODESCAN_NOMINATION:STREAM=A|B|C>>>
- [ ] N-NNN | <project> | <vector> | <file>:<line> | rec: high|med|low | y/n: 
    Summary: <max 2 lines, plain English; no symbol IDs, no jargon>
    <structured fields specific to the stream>
<<<AI_CODESCAN_NOMINATION:END>>>
```

The opening sentinel records which stream this nomination belongs to.
Pick exactly one of `A`, `B`, or `C`. Any prose before or after the
sentinels is ignored; the harness only reads the bracketed block.

You may write nothing else after the closing sentinel; one block per
iteration.

## Stream-specific fields

- **Stream A** (pre-traced flow): include `Flows: F-IDs (CWE, parameterization)` and `Source / Sink` lines.
- **Stream B** (AI-discovered candidate): include `Heuristic:` and `Symbols:` lines explaining why the static engine missed it.
- **Stream C** (proposed CodeQL model extension): include the proposed YAML model in a fenced code block.

## Hard rules

- Always keep `Summary:` to two lines maximum.
- `rec: high` if you would investigate, `rec: med` if uncertain, `rec: low` if borderline.
- Use ONLY the data given. Do not fabricate symbols, file paths, or line numbers.
- Do **not** call Edit / Write / any file-modifying tool. Print to stdout only.
- Do **not** call `printenv` / `env`. Use the inlined paths as printed.

If you want to read source code while deciding, use Read / Grep / Glob
against the snapshot root path inlined below.
