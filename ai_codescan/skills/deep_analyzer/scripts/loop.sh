#!/usr/bin/env bash
# Drive the deep-analyzer skill loop. See wide_nominator/scripts/loop.sh
# for the rationale: we inline the per-iteration inputs into the prompt
# body so agentic LLM CLIs (claude-code, codex) don't have to read
# environment variables — their shell sandbox blocks ``printenv`` and
# parameter expansion in many configurations.
set -euo pipefail
RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
QUEUE="$RUN_DIR/findings_queue.md"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
PROMPT="$SKILL_DIR/prompts/analyzer.md"
SOURCE_ROOT="$RUN_DIR/../source"

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

render_prompt() {
  local nomination="$1"
  local slice_file="$2"
  local finding_path="$3"
  cat "$PROMPT"
  printf '\n\n---\n\n## This iteration\n\n'
  printf 'Nomination block (from `nominations.md`):\n\n```\n%s\n```\n\n' "$nomination"
  printf 'Files you must use:\n\n'
  printf -- '- Slice JSON to read: `%s`\n' "$slice_file"
  printf -- '- Write your finding markdown to: `%s` (exactly once, do not modify other files)\n' "$finding_path"
  printf -- '- Source snapshot root (read-only): `%s`\n\n' "$SOURCE_ROOT"
  if [[ -f "$slice_file" ]]; then
    printf '## Embedded slice JSON\n\n```json\n'
    cat "$slice_file"
    printf '\n```\n'
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
  if ! render_prompt "$line" "$slice_file" "$finding_path" | invoke_llm; then
    echo "warning: $nom_id failed" >&2
    continue
  fi
  touch "$done"
done < "$QUEUE"
