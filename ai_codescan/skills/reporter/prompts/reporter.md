# Report requirements

Return only one block between these markers:

`<<<AI_CODESCAN_FINAL_REPORT>>>`

`<<<AI_CODESCAN_FINAL_REPORT:END>>>`

Use this report structure:

1. `# Security Assessment`
2. `## Executive Summary`
3. `## Engagement Scope and Coverage`
4. `## Method`
5. `## Findings at a Glance`
6. `## Detailed Findings`
7. `## Prioritized Remediation`
8. `## Limitations and Follow-up Work`

The coverage table must contain the component or activity, status, and evidence-based notes.
Use only `SCANNED`, `NOT SCANNED`, or `TODO` as a coverage status.

The findings table must contain the ID, severity, confidence, component, title, location, and
validation status. The total must equal the number of detailed findings.

For each detailed finding, include the summary, impact, affected location, evidence, reproduction
steps, proof-of-concept text or its reason for omission, and a specific fix.

Include only proof-of-concept text from the scan data. Keep it observation-only. Never operate it.
Use uppercase placeholders for target-specific URLs, tokens, keys, and identifiers.

Sort findings by severity. Preserve scanner IDs, file paths, line numbers, and validation facts.
Include every verified finding. Do not omit low-severity findings.

Do not repeat the executive summary, table text, evidence, or remediation in another section.
State missing information as a limitation or `TODO`. Do not infer it.
