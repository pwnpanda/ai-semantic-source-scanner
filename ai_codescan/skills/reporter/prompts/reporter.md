# Report requirements

Return only one block between these markers:

`<<<AI_CODESCAN_FINAL_REPORT>>>`

`<<<AI_CODESCAN_FINAL_REPORT:END>>>`

Use this report structure:

1. `# Security Assessment`
2. `## Executive Summary`
3. `## Scope and Method`
4. `## Findings at a Glance`
5. `## Detailed Findings`
6. `## Prioritized Remediation`
7. `## Coverage and Limitations`

The findings table must contain the ID, severity, title, location, and validation status.

For each detailed finding, include the impact, affected location, evidence, and specific fix.
Do not repeat the executive summary, table text, or evidence in another section.

Sort findings by severity. Preserve scanner IDs, file paths, line numbers, and validation facts.
State missing information as a limitation. Do not infer it.
