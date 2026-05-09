#!/usr/bin/env bash
set -euo pipefail
RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
PROMPT="$SKILL_DIR/prompts/walker.md"
OUT="$RUN_DIR/llm_heavy_flows.jsonl"

: > "$OUT"  # truncate so the LLM appends from a clean slate

invoke_llm() {
  if [[ -n "$LLM_CMD" ]]; then
    "$LLM_CMD"
  else
    local p
    p="$(cat -)"
    claude -p "$p"
  fi
}

AI_CODESCAN_OUT_PATH="$OUT" \
  AI_CODESCAN_REPO_MD="$RUN_DIR/inputs/repo.md" \
  AI_CODESCAN_ENTRYPOINTS_MD="$RUN_DIR/inputs/entrypoints.md" \
  AI_CODESCAN_SOURCE_ROOT="$RUN_DIR/../source" \
  invoke_llm < "$PROMPT" || {
    echo "warning: llm-heavy walker failed" >&2
  }
