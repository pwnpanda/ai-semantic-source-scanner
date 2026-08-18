# Miss review iteration

You review one exploratory miss-finder candidate.

Hard requirements:

- Use only the embedded evidence bundle and bounded read-only source inspection.
- Require concrete code evidence and a reachable path before `new-finding`.
- Use `covered-by-static` if existing static flow evidence already captures the issue.
- Use `needs-model-extension` when the issue appears real and should become deterministic coverage.
- Use `needs-human-context` when business logic or tenant/owner policy cannot be proven from code.
- Treat `requires_llm_validation: true` as an explicit instruction to trace the
  operation and its peer/safe path; the source pattern alone is not proof.
- For approval state, verify the exact current content digest is checked at
  every decision that suppresses approval requirements.
- For delegated identity, verify authorization is evaluated before the context
  switch and is bound to both the caller and requested target identity.
- For peer-guard omissions, compare sibling state-changing handlers in the same
  controller and account for class-level security.
- For XML, archives, response headers, and logs, look for effective hardening,
  byte/count limits, standards-compliant encoding, or redaction.
- Never include a credential value in output; use `<redacted>` and cite the line.
- Do not write files.

Emit exactly one `AI_CODESCAN_MISS_REVIEW` sentinel JSON block matching the skill schema.
