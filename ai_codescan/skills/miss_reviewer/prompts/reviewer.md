# Miss review iteration

You review one exploratory miss-finder candidate.

Hard requirements:

- Use only the embedded evidence bundle and bounded read-only source inspection.
- Require concrete code evidence and a reachable path before `new-finding`.
- Use `covered-by-static` if existing static flow evidence already captures the issue.
- Use `needs-model-extension` when the issue appears real and should become deterministic coverage.
- Use `needs-human-context` when business logic or tenant/owner policy cannot be proven from code.
- Do not write files.

Emit exactly one `AI_CODESCAN_MISS_REVIEW` sentinel JSON block matching the skill schema.
