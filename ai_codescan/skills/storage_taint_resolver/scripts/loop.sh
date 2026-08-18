#!/usr/bin/env bash
# Drive the storage-taint-resolver skill across the queue.
set -euo pipefail

RUN_DIR="${AICS_RUN_DIR:?missing AICS_RUN_DIR}"
SKILL_DIR="${AICS_SKILL_DIR:?missing AICS_SKILL_DIR}"
QUEUE="$RUN_DIR/storage_resolver/queue.jsonl"
PROMPT="$SKILL_DIR/prompts/resolver.md"
LLM_CMD="${AICS_LLM_CMD:-claude -p}"
AICS_LLM_CONTEXT="${AICS_LLM_CONTEXT:-}"
export AICS_LLM_CONTEXT
# shellcheck source=/dev/null
source "$(dirname "$SKILL_DIR")/item_cache.sh"

if [[ ! -f "$QUEUE" ]]; then
  echo "no queue at $QUEUE" >&2
  exit 1
fi

mkdir -p "$RUN_DIR/storage_resolver/.done"
PROPOSALS="$RUN_DIR/storage_resolver/proposals.jsonl"
touch "$PROPOSALS"

remove_candidate_proposals() {
  local call_id="$1"
  python3 - "$PROPOSALS" "$call_id" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
call_id = sys.argv[2]
kept = []
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    if isinstance(item, dict) and str(item.get("call_id") or "") != call_id:
        kept.append(json.dumps(item, sort_keys=True))
path.write_text("".join(f"{line}\n" for line in kept), encoding="utf-8")
PY
}

candidate_has_proposal() {
  local call_id="$1"
  python3 - "$PROPOSALS" "$call_id" <<'PY'
import json
import sys
from pathlib import Path

for line in Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    if isinstance(item, dict) and str(item.get("call_id") or "") == sys.argv[2]:
        raise SystemExit(0)
raise SystemExit(1)
PY
}

prune_proposals_to_queue() {
  python3 - "$QUEUE" "$PROPOSALS" <<'PY'
import json
import sys
from pathlib import Path

queue_path = Path(sys.argv[1])
proposals_path = Path(sys.argv[2])
queue_ids = []
for line in queue_path.read_text(encoding="utf-8", errors="replace").splitlines():
    if line.strip():
        queue_ids.append(str(json.loads(line).get("call_id") or ""))
latest = {}
for line in proposals_path.read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    if isinstance(item, dict) and (call_id := str(item.get("call_id") or "")):
        latest[call_id] = item
contents = "".join(
    json.dumps(latest[call_id], sort_keys=True) + "\n"
    for call_id in queue_ids
    if call_id in latest
)
proposals_path.write_text(contents, encoding="utf-8")
PY
}

invoke_llm() {
  # A provider rate limit exits non-zero. Treating that as a permanent failure
  # for the candidate means one throttle silently burns the rest of the queue,
  # so back off and retry before giving up on a candidate.
  local call_id="$1" candidate="$2"
  local attempt delay retries
  delay="${AICS_LLM_RETRY_DELAY:-60}"
  retries="${AICS_LLM_RETRIES:-5}"
  for attempt in $(seq 1 "$retries"); do
    if AICS_CANDIDATE="$candidate" \
      AICS_REPO_MD="$RUN_DIR/inputs/repo.md" \
      CALL_ID="$call_id" \
      "$LLM_CMD" <"$PROMPT"; then
      return 0
    fi
    [[ "$attempt" -eq "$retries" ]] && break
    printf 'llm attempt %d failed for %s; retrying in %ds\n' "$attempt" "$call_id" "$delay" >&2
    sleep "$delay"
    delay=$((delay * 2))
  done
  return 1
}

failures=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  call_id=$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["call_id"])')
  done_marker="$RUN_DIR/storage_resolver/.done/${call_id}"
  item_fingerprint="$(
    aics_item_fingerprint \
      "$line" \
      "$PROMPT" "$RUN_DIR/inputs/repo.md" "$RUN_DIR/inputs/schema.taint.yml"
  )"
  marker_fingerprint=""
  if [[ -f "$done_marker" ]]; then
    marker_fingerprint="$(cat "$done_marker")"
  fi
  if [[ "$marker_fingerprint" == "$item_fingerprint" ]] &&
    candidate_has_proposal "$call_id"; then
    continue
  fi
  rm -f "$done_marker"
  remove_candidate_proposals "$call_id"
  invoke_llm "$call_id" "$line" || {
    echo "warning: candidate $call_id failed" >&2
    rm -f "$done_marker"
    failures=$((failures + 1))
    continue
  }
  if ! candidate_has_proposal "$call_id"; then
    echo "warning: candidate $call_id produced no structured proposal" >&2
    failures=$((failures + 1))
    continue
  fi
  printf '%s\n' "$item_fingerprint" >"$done_marker"
done <"$QUEUE"
if [[ "$failures" -ne 0 ]]; then
  echo "resolver incomplete: $failures required candidate(s) failed" >&2
  exit 1
fi
prune_proposals_to_queue
