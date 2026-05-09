# Validator iteration

You write one PoC at a time. Inputs:

- `$AI_CODESCAN_FINDING_PATH` — finding markdown with `status: unverified`.
- `$AI_CODESCAN_SLICE_FILE` — JSON describing the source/sink path.
- `$AI_CODESCAN_SOURCE_ROOT` — read-only snapshot tree.
- `$AI_CODESCAN_POC_DIR` — where to write the PoC file (one file, exactly).
- `$AI_CODESCAN_REPO_MD` — `repo.md` for language/framework detection.
- `$AI_CODESCAN_HINTS_PATH` — optional per-CWE rubric (read it if it exists).
- `$AI_CODESCAN_TARGET_LANG` — optional explicit language.

## Pick the PoC language

Match the target's primary language so the PoC speaks the same dialect:

| Target stack | PoC language | File name |
|---|---|---|
| Node / JS / TS frameworks (Express, Next, Nest, Fastify) | `javascript` | `poc.js` |
| PHP frameworks (Laravel, Symfony, WordPress) | `php` | `poc.php` |
| Ruby on Rails | `ruby` | `poc.rb` |
| Go (gin, echo, chi, net/http) | `go` | `poc.go` |
| Shell-pipeline reproduction unavoidable | `shell` | `poc.sh` |
| Anything else, or you're not sure | `python` (fallback) | `poc.py` |

If `$AI_CODESCAN_TARGET_LANG` is set, use that. Otherwise read `repo.md`'s
"Languages" line and pick the first canonical match. Default to Python.

The runner invokes the right interpreter automatically (`node poc.js`,
`php poc.php`, `ruby poc.rb`, `go run poc.go`, `python3 poc.py`, `sh poc.sh`).

## What the PoC must do

The PoC must satisfy the **per-CWE rubric** in `$AI_CODESCAN_HINTS_PATH`
(when present). That file lists concrete proof criteria for the bug class —
e.g. for SQLi: "force a SQL parser error" or "extract data not normally
accessible". Pick one criterion and write the PoC to satisfy it.

If no hints file exists, follow the generic protocol below.

## Output protocol — JSON verdict (preferred)

Print a final JSON line on stdout with this exact shape:

```
{"verdict": "vulnerable" | "not_vulnerable" | "inconclusive",
 "evidence": ["one line per concrete observation"],
 "confidence": 0.0..1.0}
```

The runner parses this. `vulnerable` flips the finding to `verified`,
`not_vulnerable` to `rejected`, `inconclusive` to `poc_inconclusive`.

`evidence` should reference observable facts from the run, e.g.
`"response body contains 'You have an error in your SQL syntax'"` or
`"PoC wrote /tmp/marker after triggering the dangerous sink"`.

## Backward-compat fallback

If you cannot emit JSON for any reason, you may instead:

1. Print exactly the literal `OK_VULN` on stdout when the bug triggers.
2. Print `BENIGN` and exit 0 when a sanitiser blocks the exploit.
3. Exit non-zero with a short explanation when the path can't be reproduced offline.

## Sandboxing

The PoC runs inside a hardened container with no network access. Do NOT
make outbound requests; simulate user input as inline strings. Out-of-band
beacons are not yet wired up (Phase 2F).

## Output

- Use the Write tool exactly once.
- Path must be `$AI_CODESCAN_POC_DIR/poc.<ext>` matching the language picked.
- Do not edit any other files.
