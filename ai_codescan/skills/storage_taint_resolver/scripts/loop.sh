#!/usr/bin/env bash
# Drive the storage-taint-resolver skill across the queue.
set -euo pipefail

RUN_DIR="${AICS_RUN_DIR:?missing AICS_RUN_DIR}"
SKILL_DIR="${AICS_SKILL_DIR:?missing AICS_SKILL_DIR}"
QUEUE="$RUN_DIR/storage_resolver/queue.jsonl"
PROMPT="$SKILL_DIR/prompts/resolver.md"
LLM_CMD="${AICS_LLM_CMD:-claude -p}"

if [[ ! -f "$QUEUE" ]]; then
  echo "no queue at $QUEUE" >&2
  exit 1
fi

mkdir -p "$RUN_DIR/storage_resolver/.done"
: > "$RUN_DIR/storage_resolver/proposals.jsonl"  # truncate prior run

invoke_llm() {
  # A provider rate limit exits non-zero. Treating that as a permanent failure
  # for the candidate means one throttle silently burns the rest of the queue,
  # so back off and retry before giving up on a candidate.
  local call_id="$1" candidate="$2"
  local attempt delay
  delay="${AICS_LLM_RETRY_DELAY:-60}"
  for attempt in $(seq 1 "${AICS_LLM_RETRIES:-5}"); do
    if AICS_CANDIDATE="$candidate" \
      AICS_REPO_MD="$RUN_DIR/inputs/repo.md" \
      CALL_ID="$call_id" \
      "$LLM_CMD" < "$PROMPT"; then
      return 0
    fi
    printf 'llm attempt %d failed for %s; retrying in %ds\n' "$attempt" "$call_id" "$delay" >&2
    sleep "$delay"
    delay=$(( delay * 2 ))
  done
  return 1
}

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  call_id=$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["call_id"])')
  done_marker="$RUN_DIR/storage_resolver/.done/${call_id}"
  if [[ -f "$done_marker" ]]; then
    continue
  fi
  invoke_llm "$call_id" "$line" || {
    echo "warning: candidate $call_id failed" >&2
    continue
  }
done < "$QUEUE"
