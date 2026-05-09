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

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  call_id=$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["call_id"])')
  done_marker="$RUN_DIR/storage_resolver/.done/${call_id}"
  if [[ -f "$done_marker" ]]; then
    continue
  fi
  AICS_CANDIDATE="$line" \
    AICS_REPO_MD="$RUN_DIR/inputs/repo.md" \
    CALL_ID="$call_id" \
    "$LLM_CMD" < "$PROMPT" || {
      echo "warning: candidate $call_id failed" >&2
      continue
    }
done < "$QUEUE"
