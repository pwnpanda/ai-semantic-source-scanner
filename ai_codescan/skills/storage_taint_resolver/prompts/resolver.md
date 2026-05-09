# Storage taint resolver iteration

You are resolving one storage call site at a time.

`$AICS_CANDIDATE` — JSON for the current call:
```json
{"call_id": "S-xxx",
 "file": "/abs/path/to/source.ts",
 "line": 42,
 "callee": "cache.set",
 "code_snippet": "cache.set(`user:${userId}:profile`, body)",
 "context_lines": ["function setProfile(userId: string, body: any) {", "  ...", "}"]}
```

`$AICS_REPO_MD` — stack/framework hints.

## Decide a storage_id

1. Re-read the snippet and surrounding lines.
2. Identify the receiver (cache/redis/queue/fs/etc.) and the operation.
3. Recover the canonical key pattern. Use `*` for runtime holes you can't
   pin down (typically user-controlled IDs).
4. Emit the JSON record described in `SKILL.md` and append one line to
   `$AICS_RUN_DIR/storage_resolver/proposals.jsonl`. Then `touch
   $AICS_RUN_DIR/storage_resolver/.done/$CALL_ID`.

If you cannot recover a meaningful key (the call is dispatched via reflection,
the topic is a function-arg with no traceable bound, etc.), emit
`{"call_id": "S-xxx", "storage_id": null, "confidence": 0.0, "rationale": "..."}`
and move on.

## Hard rules

- Do not duplicate an existing entry in `$AICS_RUN_DIR/inputs/schema.taint.yml`.
- Do not modify any other file.
- Use Read/Grep/Glob to inspect surrounding code; do NOT execute anything.
