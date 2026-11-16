---
name: reporter
description: Create the end-of-engagement security assessment after validation. Combine all verified scanner findings into one evidence-based report with explicit coverage and safe reproduction guidance.
allowed-tools: Read
license: apache-2.0
---

# Final Reporter

Create one final report from all embedded verified findings.

Use only facts in the scan data. Do not invent exploitability, business impact, affected code,
or remediation details.

State each finding once. Keep evidence with its finding. Put shared remediation work only in the
prioritized remediation section.

Read `references/end-of-engagement.md` before you create the report. It adapts the
`reporting-skill` baseline to the scanner output format.

Use the exact structure and output markers in `prompts/reporter.md`.
