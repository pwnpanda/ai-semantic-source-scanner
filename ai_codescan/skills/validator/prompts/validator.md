# Validator iteration

You write one PoC at a time. Inputs:

- `$AI_CODESCAN_FINDING_PATH` — finding markdown with `status: unverified`.
- `$AI_CODESCAN_SLICE_FILE` — JSON describing the source/sink path.
- `$AI_CODESCAN_SOURCE_ROOT` — read-only snapshot tree.
- `$AI_CODESCAN_POC_DIR` — where to write the PoC file (one file, exactly).
- `$AI_CODESCAN_REPO_MD` — `repo.md` for language/framework detection.
- `$AI_CODESCAN_TARGET_LANG` — optional explicit language (one of: `python`,
  `javascript`, `typescript`, `php`, `ruby`, `go`, `shell`).

## Pick the PoC language

Match the target's primary language so the PoC speaks the same dialect:

| Target stack | PoC language | File name |
|---|---|---|
| Node / JS / TS frameworks (Express, Next, Nest, Fastify) | `javascript` | `poc.js` |
| PHP frameworks (Laravel, Symfony, WordPress) | `php` | `poc.php` |
| Ruby on Rails | `ruby` | `poc.rb` |
| Go (gin, echo, chi, net/http) | `go` | `poc.go` |
| Shell-pipeline reproduction is unavoidable | `shell` | `poc.sh` |
| Anything else, or you're not sure | `python` (fallback) | `poc.py` |

If `$AI_CODESCAN_TARGET_LANG` is set, use that. Otherwise read `repo.md`'s
"Languages" line and pick the first canonical match. Default to Python.

The runner will invoke the PoC with the right interpreter automatically
(`node poc.js`, `php poc.php`, `ruby poc.rb`, `go run poc.go`, `python3 poc.py`,
`sh poc.sh`).

## What the PoC must do

1. Run with no arguments. No CLI flags, no env vars besides what the runtime
   normally exposes.
2. Print **exactly** the literal string `OK_VULN` on stdout when the
   vulnerability triggers, then exit 0. The string is the success signal.
3. Print `BENIGN` and exit 0 when a sanitiser blocks the exploit.
4. Exit non-zero with a short explanation when the path can't be reproduced
   offline (e.g. it requires a real database connection).
5. Run inside a sandboxed container with no network access. Do NOT make any
   outbound requests; simulate user input as inline strings.
6. Keep the PoC self-contained (no `import` from the target tree). Inline the
   minimum amount of vulnerable code you need to reproduce the flow.

## Output protocol

- Use the Write tool exactly once.
- Path must be `$AI_CODESCAN_POC_DIR/poc.<ext>` matching the language picked.
- Do not edit any other files.
