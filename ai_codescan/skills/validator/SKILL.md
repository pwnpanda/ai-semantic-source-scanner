---
name: validator
description: Per-finding PoC author. Reads a finding doc, writes poc.py or poc.sh that exercises the exact path, and emits OK_VULN on stdout when the exploit succeeds.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
license: apache-2.0
---

# Validator

For each finding still `status: unverified`:

1. Read the finding markdown from `$AI_CODESCAN_FINDING_PATH`.
2. Read the slice JSON from `$AI_CODESCAN_SLICE_FILE` (same as the analyzer received).
3. Write a PoC script to `$AI_CODESCAN_POC_PATH` (`poc.py` or `poc.sh`).
4. The script MUST:
   - Reproduce the exact source-to-sink path described in the finding.
   - Print exactly the literal string `OK_VULN` on stdout if the vulnerability triggers.
   - Print `BENIGN` and exit 0 if the path turns out to be safe (sanitiser detected, etc.).
   - Avoid any network access — the sandbox blocks it anyway.
5. Stop after writing the file. The orchestrator runs the PoC inside the sandbox.
