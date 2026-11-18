# Deep analysis iteration

You analyse one candidate at a time. All inputs you need (the nomination
block, the evidence bundle JSON contents, and the read-only snapshot root) are
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
finding_id: <finding id from this iteration>
nomination_id: <nomination id from this iteration>
flow_id: <flow id if present in bundle, otherwise empty string>
cwe: CWE-XX
status: <unverified or rejected>
analysis_verdict: <true-positive | false-positive | inconclusive | needs-model-extension>
confidence: <low | medium | high>
exploitability: <demonstrated | latent | unknown>
unmet_prerequisites:
  - <required future code, deployment, or trust-boundary condition>
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
- If the bundle is too thin to be sure, set `status: unverified` and explain in Open questions.
- Use `analysis_verdict: needs-model-extension` when the issue looks real but the static model did not capture the right source, sink, or semantic condition.
- Use `analysis_verdict: inconclusive` when evidence is insufficient; do not upgrade weak evidence to true-positive.
- Use `exploitability: latent` when the unsafe primitive exists but material impact needs an unmet condition.
- Keep latent findings visible. Do not reject them only because the current target lacks an impact path.
- List each required future condition under `unmet_prerequisites`.
- Use `exploitability: unknown` when evidence is too thin to identify a specific unmet condition.
- Use `unmet_prerequisites: []` for `demonstrated` and `unknown` findings.
- A same-origin SSRF primitive is latent when no sensitive same-origin endpoint is currently known.
- Treat comments and project documents as intent, not proof of a security control.
- Reject a candidate only when code proves mitigation or non-reachability.
- Keep a plausible security boundary failure unverified when policy or deployment facts are unknown.
- For sensitive actions, treat a fail-open local prompt as unsafe unless the server enforces the same control.
- For object identifiers, require code that binds the caller to the requested object. Authentication alone is not object authorization.
- One finding block per iteration. Do **not** call Write / Edit.
