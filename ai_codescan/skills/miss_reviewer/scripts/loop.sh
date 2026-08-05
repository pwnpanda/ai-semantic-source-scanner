#!/usr/bin/env bash
# Drive the miss-reviewer skill loop. Same protocol as deep_analyzer:
# inputs (bundle JSON, miss candidate record) are inlined into the prompt,
# and the LLM emits AI_CODESCAN_MISS_REVIEW sentinel JSON on stdout.
#
# Each iteration writes:
#   $REVIEW_DIR/<candidate_id>.json  — the raw sentinel payload, on success
#   $RUN_DIR/.done-miss-review/<candidate_id>.stdout — the full LLM stdout
# Failed iterations leave no review file so a re-run can retry.
set -euo pipefail
RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
QUEUE="${AI_CODESCAN_MISS_QUEUE:-$RUN_DIR/miss_review_queue.jsonl}"
REVIEW_DIR="${AI_CODESCAN_MISS_REVIEW_DIR:-$RUN_DIR/miss_reviews}"
BUNDLES_DIR="${AI_CODESCAN_MISS_BUNDLES_DIR:-$RUN_DIR/miss_bundles}"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
PROMPT="$SKILL_DIR/prompts/reviewer.md"
SOURCE_ROOT="${AI_CODESCAN_SOURCE_ROOT:-$RUN_DIR/../source}"

[[ -f "$QUEUE" ]] || { echo "no miss-review queue at $QUEUE" >&2; exit 1; }
mkdir -p "$REVIEW_DIR" "$RUN_DIR/.done-miss-review"

invoke_llm() {
  # Rate limits surface as a non-zero exit from the provider CLI. Callers
  # treat that as a permanent per-item failure and move on, so a throttle
  # part-way through a long queue silently burns every remaining item.
  # Back off and retry instead; only a persistent failure is fatal.
  #
  # stdin is consumed by the first attempt, so buffer the prompt to replay it.
  local prompt_file attempt delay rc
  prompt_file="$(mktemp)"
  cat - > "$prompt_file"
  delay="${AI_CODESCAN_LLM_RETRY_DELAY:-60}"
  rc=1
  for attempt in $(seq 1 "${AI_CODESCAN_LLM_RETRIES:-5}"); do
    if [[ -n "$LLM_CMD" ]]; then
      "$LLM_CMD" < "$prompt_file" && rc=0
    else
      claude -p "$(cat "$prompt_file")" && rc=0
    fi
    [[ "$rc" -eq 0 ]] && break
    printf 'llm attempt %d failed; retrying in %ds … ' "$attempt" "$delay" >&2
    sleep "$delay"
    delay=$(( delay * 2 ))
  done
  rm -f "$prompt_file"
  return "$rc"
}

render_prompt() {
  local candidate_json="$1"
  local bundle_path="$2"
  cat "$PROMPT"
  printf '\n\n---\n\n## This iteration\n\n'
  printf 'Source snapshot root: `%s`\n\n' "$SOURCE_ROOT"
  printf '## Embedded miss candidate\n\n```json\n%s\n```\n\n' "$candidate_json"
  if [[ -n "$bundle_path" && -f "$bundle_path" ]]; then
    printf '## Embedded evidence bundle JSON\n\n```json\n'
    cat "$bundle_path"
    printf '\n```\n'
  fi
}

write_review_from_stdout() {
  local llm_out="$1"
  local review_path="$2"
  python3 - "$llm_out" "$review_path" <<'PY'
import re
import sys
from pathlib import Path

raw = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
out_path = Path(sys.argv[2])
match = re.search(
    r"<<<AI_CODESCAN_MISS_REVIEW>>>\s*(\{.*?\})\s*<<<AI_CODESCAN_MISS_REVIEW:END>>>",
    raw,
    re.DOTALL,
)
if not match:
    print("no review block in LLM output", file=sys.stderr)
    sys.exit(2)
out_path.write_text(match.group(1).strip() + "\n", encoding="utf-8")
PY
}

total=$(grep -c '^' "$QUEUE" || true)
done_count=$(find "$RUN_DIR/.done-miss-review" -maxdepth 1 -type f ! -name '*.stdout' 2>/dev/null | wc -l | tr -d ' ')
echo "[miss-review] queue: $total candidates ($done_count already done)" >&2

idx=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  idx=$((idx + 1))
  candidate_id=$(printf '%s' "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('id',''))" 2>/dev/null || true)
  if [[ -z "$candidate_id" ]]; then
    echo "[miss-review] $idx/$total ??? … skip (no candidate id)" >&2
    continue
  fi
  done_marker="$RUN_DIR/.done-miss-review/${candidate_id}"
  if [[ -f "$done_marker" ]]; then
    echo "[miss-review] $idx/$total $candidate_id … skip (already done)" >&2
    continue
  fi
  bundle_path=$(printf '%s' "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('bundle_json',''))" 2>/dev/null || true)
  if [[ -z "$bundle_path" || ! -f "$bundle_path" ]]; then
    bundle_path="$BUNDLES_DIR/${candidate_id}.json"
  fi
  printf '[miss-review] %d/%d %s … ' "$idx" "$total" "$candidate_id" >&2
  iter_log="$RUN_DIR/.done-miss-review/${candidate_id}.stdout"
  start_ts=$(date +%s)
  if ! render_prompt "$line" "$bundle_path" | invoke_llm > "$iter_log"; then
    echo "FAIL (llm error)" >&2
    continue
  fi
  review_path="$REVIEW_DIR/${candidate_id}.json"
  if ! write_review_from_stdout "$iter_log" "$review_path"; then
    elapsed=$(( $(date +%s) - start_ts ))
    echo "FAIL no review block (${elapsed}s)" >&2
    continue
  fi
  elapsed=$(( $(date +%s) - start_ts ))
  classification=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('classification',''))" "$review_path" 2>/dev/null || echo unknown)
  echo "ok → ${classification} (${elapsed}s)" >&2
  touch "$done_marker"
done < "$QUEUE"
echo "[miss-review] done" >&2
