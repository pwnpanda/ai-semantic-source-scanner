#!/usr/bin/env bash
set -euo pipefail
RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
QUEUE="$RUN_DIR/findings_queue.md"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
PROMPT="$SKILL_DIR/prompts/analyzer.md"

[[ -f "$QUEUE" ]] || { echo "no $QUEUE" >&2; exit 1; }
mkdir -p "$RUN_DIR/findings" "$RUN_DIR/.done-analyze"

invoke_llm() {
  if [[ -n "$LLM_CMD" ]]; then
    "$LLM_CMD"
  else
    local p
    p="$(cat -)"
    claude -p "$p"
  fi
}

while IFS= read -r line; do
  if [[ ! "$line" =~ ^-\ \[\ \]\ (N-[A-Za-z0-9_-]+)\ \|\ ([^|]+)\ \|\ ([^|]+)\ \| ]]; then
    continue
  fi
  nom_id="${BASH_REMATCH[1]}"
  done="$RUN_DIR/.done-analyze/${nom_id}"
  [[ -f "$done" ]] && continue
  finding_id="F-${nom_id#N-}"
  finding_path="$RUN_DIR/findings/${finding_id}.md"
  slice_file="$RUN_DIR/slices/${nom_id}.json"
  if [[ ! -f "$slice_file" ]]; then
    echo "no slice for $nom_id (skipping)" >&2
    continue
  fi

  AI_CODESCAN_SLICE_FILE="$slice_file" \
    AI_CODESCAN_NOMINATION="$line" \
    AI_CODESCAN_SOURCE_ROOT="$RUN_DIR/../source" \
    AI_CODESCAN_FINDING_PATH="$finding_path" \
    invoke_llm < "$PROMPT" || {
      echo "warning: $nom_id failed" >&2
      continue
    }
  touch "$done"
done < "$QUEUE"
