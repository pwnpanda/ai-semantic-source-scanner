# Deep analysis iteration

You analyse one taint flow at a time. All inputs you need (the nomination
block, the slice JSON contents, and the read-only snapshot root) are
inlined below in the "This iteration" section.

Do **not** call `printenv` or `env`. Use the absolute paths exactly as
printed for Read / Grep — but do **not** call Edit / Write or any other
file-modifying tool. Emit the finding markdown to stdout via the
sentinel protocol below; the harness writes the file for you.

## Output protocol — sentinel-bracketed finding on stdout

Print exactly this on stdout (status one of: `unverified`, `rejected`):

```
<<<AI_CODESCAN_FINDING:STATUS=unverified|rejected>>>
---
title: <short, plain English>
cwe: CWE-XX
status: <unverified or rejected>
---

## Summary
<2-3 sentences in plain English>

## Path
- file:line: short paraphrase
- ...

## Evidence
```<lang>
<sink code excerpt + missing sanitiser>
```

## Why-real
<concrete exploitability argument; or argue it's a false positive if status: rejected>

## Mitigation
<concrete code change>

## Open questions
<what a human reviewer should verify>
<<<AI_CODESCAN_FINDING:END>>>
```

Hard rules:
- Use ONLY data given. Do not fabricate file paths or line numbers.
- If the slice is too thin to be sure, set `status: unverified` and explain in Open questions.
- One finding block per iteration. Do **not** call Write / Edit.
