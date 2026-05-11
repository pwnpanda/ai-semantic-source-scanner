#!/usr/bin/env bash
# LLM-heavy walker driver. Inlines inputs (source-root path, entrypoint
# inventory, output path, bug-class filter) into the prompt body so the
# LLM doesn't have to read environment variables — modern agentic CLIs
# sandbox shell access and block ``printenv`` / parameter expansion.
set -euo pipefail
RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
PROMPT="$SKILL_DIR/prompts/walker.md"
OUT="$RUN_DIR/llm_heavy_flows.jsonl"
SOURCE_ROOT="$RUN_DIR/../source"
REPO_MD="$RUN_DIR/inputs/repo.md"
ENTRY_MD="$RUN_DIR/inputs/entrypoints.md"
TARGET_BUG_CLASSES="${AI_CODESCAN_TARGET_BUG_CLASSES:-}"

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

render_prompt() {
  cat "$PROMPT"
  printf '\n\n---\n\n## This run\n\n'
  printf 'Files you must use:\n\n'
  printf -- '- Source snapshot root (read-only; use Read/Grep here): `%s`\n' "$SOURCE_ROOT"
  printf -- '- Repo overview: `%s`\n' "$REPO_MD"
  printf -- '- Entrypoints inventory (start traversal here): `%s`\n' "$ENTRY_MD"
  printf -- '- Append your JSONL flows to: `%s`\n' "$OUT"
  if [[ -n "$TARGET_BUG_CLASSES" ]]; then
    printf -- '- Filter focus to these bug classes: `%s`\n' "$TARGET_BUG_CLASSES"
  fi
  printf '\n'
  if [[ -f "$REPO_MD" ]]; then
    printf '## Embedded `repo.md`\n\n```markdown\n'
    cat "$REPO_MD"
    printf '\n```\n\n'
  fi
  if [[ -f "$ENTRY_MD" ]]; then
    printf '## Embedded `entrypoints.md`\n\n```markdown\n'
    cat "$ENTRY_MD"
    printf '\n```\n'
  fi
}

if ! render_prompt | invoke_llm; then
  echo "warning: llm-heavy walker failed" >&2
fi
