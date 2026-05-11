# Deep analysis iteration

You analyse one taint flow at a time. All inputs you need (the nomination
block, the slice JSON contents, the absolute path where you must write
the finding markdown, and the read-only snapshot root) are inlined below
in the "This iteration" section. Do **not** call `printenv` or `env` —
use the absolute paths exactly as printed.

Required output: write the finding markdown file exactly once, with
valid frontmatter and a 6-section body:

1. **Summary** — 2-3 sentences in plain English.
2. **Path** — bullet list of `(file:line: short paraphrase)` for every step.
3. **Evidence** — fenced code blocks of the source-controlled sink and any sanitisers that should have fired but didn't.
4. **Why-real** — argue concretely why this is exploitable. If you suspect it's a false positive, say so and propose `status: rejected`.
5. **Mitigation** — concrete code change.
6. **Open questions** — what you'd want a human reviewer to verify.

Hard rules:
- Use ONLY data given. Do not fabricate file paths or line numbers.
- If the slice is too thin to be sure, set `status: unverified` in the frontmatter and explain in Open questions.
- One finding file per iteration. Never edit other files.
