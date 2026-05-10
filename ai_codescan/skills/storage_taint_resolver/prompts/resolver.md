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

## Examples by language

Pattern shape: `<kind>:<canonical-template>` where holes are `*`. Real
deployments often interpolate one or two attacker-controlled fields
(typically a user / tenant / record id); replace those with `*`.

  * **JS / TS** — `cache.set(\`user:${userId}:profile\`, body)`
    → `cache:user:*:profile` (kind=`cache_key`).
  * **Python** — `redis.set(f"user:{user_id}:session", token)`
    → `cache:user:*:session` (kind=`cache_key`).
  * **Java** — `redisTemplate.opsForValue().set("orders:" + orderId, body)`
    → `cache:orders:*` (kind=`cache_key`). For Spring Kafka:
    `kafkaTemplate.send("notifications-" + tenant, msg)`
    → `queue:notifications-*` (kind=`queue_topic`).
  * **Go** — `rdb.Set(ctx, fmt.Sprintf("auth:%s:token", userID), v, ttl)`
    → `cache:auth:*:token`. For Kafka via Confluent:
    `producer.Produce(&kafka.Message{Topic: &topic, ...})` where topic is
    `"events." + suffix` → `queue:events.*`.
  * **Ruby** — `Rails.cache.write("profile/#{id}/settings", v)`
    → `cache:profile/*/settings`. For Sidekiq:
    `Sidekiq::Client.push("queue" => "high_priority", ...)`
    → `queue:high_priority`.
  * **C# / .NET** — `_cache.Set($"user:{userId}:claims", v)`
    → `cache:user:*:claims`. Azure Service Bus:
    `sender.SendMessageAsync(new ServiceBusMessage(payload), "tenant-" + t)`
    → `queue:tenant-*`.
  * **PHP** — `$wpdb->update($table, $data, ['user_id' => $id])`
    → `sql:<table>.user_id` (kind=`sql_column`). Laravel cache:
    `Cache::put("post:{$slug}:html", $html)` → `cache:post:*:html`.

When the same key shape appears across multiple languages in the repo,
emit a single canonical `storage_id`; round-2 fixpoint correlates writes
across languages once the locations land in `schema.taint.yml`.

## Hard rules

- Do not duplicate an existing entry in `$AICS_RUN_DIR/inputs/schema.taint.yml`.
- Do not modify any other file.
- Use Read/Grep/Glob to inspect surrounding code; do NOT execute anything.
