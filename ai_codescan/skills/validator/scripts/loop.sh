#!/usr/bin/env bash
set -euo pipefail
RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
PROMPT="$SKILL_DIR/prompts/validator.md"
FINDINGS_DIR="$RUN_DIR/findings"

[[ -d "$FINDINGS_DIR" ]] || { echo "no $FINDINGS_DIR" >&2; exit 1; }
mkdir -p "$RUN_DIR/sandbox" "$RUN_DIR/.done-validate"

invoke_llm() {
  if [[ -n "$LLM_CMD" ]]; then
    "$LLM_CMD"
  else
    local p
    p="$(cat -)"
    claude -p "$p"
  fi
}

for finding in "$FINDINGS_DIR"/*.md; do
  [[ -f "$finding" ]] || continue
  finding_id="$(basename "$finding" .md)"
  done_marker="$RUN_DIR/.done-validate/${finding_id}"
  [[ -f "$done_marker" ]] && continue

  status_line="$(grep -E '^status:' "$finding" | head -1 || true)"
  if [[ "$status_line" != *"unverified"* ]]; then
    continue
  fi

  nom_id="${finding_id#F-}"
  slice_file="$RUN_DIR/slices/N-${nom_id}.json"
  poc_dir="$RUN_DIR/sandbox/${finding_id}"
  mkdir -p "$poc_dir"
  poc_path="$poc_dir/poc.py"

  AI_CODESCAN_FINDING_PATH="$finding" \
    AI_CODESCAN_SLICE_FILE="$slice_file" \
    AI_CODESCAN_SOURCE_ROOT="$RUN_DIR/../source" \
    AI_CODESCAN_POC_PATH="$poc_path" \
    invoke_llm < "$PROMPT" || {
      echo "warning: $finding_id PoC author failed" >&2
      continue
    }
  touch "$done_marker"
done
