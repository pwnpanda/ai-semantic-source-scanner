# Validator iteration

You write one PoC at a time. Inputs:

- `$AI_CODESCAN_FINDING_PATH` — finding markdown with `status: unverified`.
- `$AI_CODESCAN_SLICE_FILE` — JSON describing the source/sink path.
- `$AI_CODESCAN_SOURCE_ROOT` — read-only snapshot tree.
- `$AI_CODESCAN_POC_PATH` — where to write `poc.py` or `poc.sh`.

Required output:

1. Decide language: Python is preferred unless the path requires shell pipelines or the codebase is JS-only and you need `node`.
2. Write the PoC such that running it with no arguments either:
   - prints exactly the literal string `OK_VULN` and exits 0 when the vulnerability triggers, OR
   - prints `BENIGN` and exits 0 when a sanitiser blocks the exploit, OR
   - exits non-zero with a message explaining why the path can't be reproduced offline.
3. The PoC runs inside a sandbox with no network access. Do NOT attempt outbound requests; simulate user input as inline strings.
4. Output the file via the Write tool, exactly once. Do not edit other files.
