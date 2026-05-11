# Validator iteration

You write one PoC at a time. All inputs you need (the finding markdown,
the slice JSON, the absolute path of the PoC directory you must write
into, `repo.md`, the optional per-CWE hint rubric, and the optional
target language) are inlined below in the "This iteration" section.

Do **not** call `printenv` or `env`. Use the absolute paths exactly as
printed.

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

If a target language is specified in "This iteration", use that.
Otherwise read `repo.md`'s "Languages" line and pick the first canonical
match. Default to Python.

The runner invokes the right interpreter automatically (`node poc.js`,
`php poc.php`, `ruby poc.rb`, `go run poc.go`, `python3 poc.py`, `sh poc.sh`).

## What the PoC must do

The PoC must satisfy the **per-CWE rubric** in the embedded hint rubric
section below (when present). It lists concrete proof criteria for the
bug class — e.g. for SQLi: "force a SQL parser error" or "extract data
not normally accessible". Pick one criterion and write the PoC to satisfy
it.

If no hint rubric was inlined, follow the generic protocol below.

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
- The PoC path must be `<inlined poc_dir>/poc.<ext>` matching the language picked.
- Do not edit any other files.
