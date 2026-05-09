---
name: storage-taint-resolver
description: Layer 5 storage-id resolver. Reads dynamic cache/queue/file calls that the static analyser couldn't resolve and proposes canonical storage_id strings with confidence levels.
allowed-tools: Read, Write, Glob, Grep
license: apache-2.0
---

# Storage Taint Resolver

Round 1+2 of Layer 5 taint analysis use a static SQL/ORM detector (sqlglot
parsers + regex heuristics). That covers the easy cases: `db.query("SELECT
... FROM users")` resolves to `sql:users.<col>`. But many real apps use
**dynamic** storage operations the static analyser can't pin down:

```
cache.set(`user:${userId}:profile`, body)        // cache key has a runtime hole
queue.publish(getTopicName(req.body.kind), data)  // topic name is computed
```

You receive the call sites the static analyser flagged as unresolved and
propose a canonical `storage_id` for each, plus a confidence and a short
rationale.

## Inputs

- `$AICS_RUN_DIR/storage_resolver/queue.jsonl` — one record per unresolved call:
  ```json
  {"call_id": "S-xxx", "file": "/abs/path.ts", "line": 42,
   "callee": "cache.set", "code_snippet": "cache.set(`user:${userId}:profile`, body)",
   "context_lines": ["...", "..."]}
  ```
- `$AICS_RUN_DIR/inputs/repo.md` — stack/framework context.
- `$AICS_RUN_DIR/inputs/schema.taint.yml` — current annotations (do not duplicate entries).

## Output

For each call you process, append exactly one record to
`$AICS_RUN_DIR/storage_resolver/proposals.jsonl`:

```json
{"call_id": "S-xxx", "storage_id": "cache:user:*:profile",
 "kind": "cache_key", "confidence": 0.85,
 "rationale": "Template literal `user:${userId}:profile`; user id is the only hole."}
```

`storage_id` conventions:

| Kind | Format | Example |
|---|---|---|
| `cache_key` | `cache:<key-pattern>` (use `*` for runtime holes) | `cache:user:*:profile` |
| `queue_topic` | `queue:<topic>` (use `*` if dynamic) | `queue:order.created` |
| `file_path` | `fs:<canonical-path>` | `fs:/var/uploads/*` |
| `env_var` | `env:<NAME>` | `env:DATABASE_URL` |
| `config_key` | `config:<file>:<dotted-key>` | `config:app.toml:auth.jwt_secret` |

`confidence` 0.0–1.0:
- **0.9–1.0** — pattern is fully literal except for trivially substitutable holes (user id, etc.)
- **0.6–0.9** — pattern recovered with one moderate inference (e.g. dispatch table lookup)
- **0.4–0.6** — best-guess; key is partly synthesized at runtime
- **< 0.4** — would skip; emit `"storage_id": null` and explain why

## Loop

Process one call at a time via `$AICS_RUN_DIR/storage_resolver/scripts/loop.sh`.
Read the queue, append your proposal, mark the call done in
`$AICS_RUN_DIR/storage_resolver/.done/<call_id>`. Atomic line-claim like the
other skills.
