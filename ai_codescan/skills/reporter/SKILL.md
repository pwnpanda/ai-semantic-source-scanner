---
name: reporter
description: Create the final security assessment after validation. Combine verified scanner findings into one concise, standardized report without duplicate evidence or remediation text.
allowed-tools: Read
license: apache-2.0
---

# Final Reporter

Create one final report from the embedded verified findings.

Use only facts in the scan data. Do not invent exploitability, business impact, affected code,
or remediation details.

State each finding once. Keep evidence with its finding. Put shared remediation work only in the
prioritized remediation section.

Use the exact structure and output markers in `prompts/reporter.md`.
