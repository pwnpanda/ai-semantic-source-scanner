# Deep analysis iteration

You analyse one taint flow at a time. Inputs:

- `$AI_CODESCAN_SLICE_FILE` — JSON describing one source/sink path with file/line excerpts.
- `$AI_CODESCAN_NOMINATION` — the nomination block from `nominations.md`.
- `$AI_CODESCAN_SOURCE_ROOT` — read-only snapshot tree.

Required output: write `$AI_CODESCAN_FINDING_PATH` exactly once, with valid frontmatter and a 6-section body:

1. **Summary** — 2-3 sentences in plain English.
2. **Path** — bullet list of `(file:line: short paraphrase)` for every step.
3. **Evidence** — fenced code blocks of the source-controlled sink and any sanitisers that should have fired but didn't.
4. **Why-real** — argue concretely why this is exploitable. If you suspect it's a false positive, say so and propose `status: rejected`.
5. **Mitigation** — concrete code change.
6. **Open questions** — what you'd want a human reviewer to verify.

Hard rules:
- Use ONLY data given. Do not fabricate file paths or line numbers.
- If the slice is too thin to be sure, output `status: unverified` and explain in Open questions.
- One finding file per iteration. Never edit other files.
