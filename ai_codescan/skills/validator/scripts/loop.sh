#!/usr/bin/env bash
# Drive the validator skill loop. See wide_nominator/scripts/loop.sh for
# rationale: inputs are inlined into the prompt so the LLM doesn't have
# to read environment variables.
set -euo pipefail
RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
PROMPT="$SKILL_DIR/prompts/validator.md"
FINDINGS_DIR="$RUN_DIR/findings"
SOURCE_ROOT="$RUN_DIR/../source"
REPO_MD="$RUN_DIR/inputs/repo.md"

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

render_prompt() {
  local finding_path="$1"
  local slice_file="$2"
  local poc_dir="$3"
  local hints_path="$4"
  local target_lang="$5"
  cat "$PROMPT"
  printf '\n\n---\n\n## This iteration\n\n'
  printf 'Files you must use:\n\n'
  printf -- '- Finding markdown (read-only): `%s`\n' "$finding_path"
  printf -- '- Slice JSON: `%s`\n' "$slice_file"
  printf -- '- Source snapshot root (read-only): `%s`\n' "$SOURCE_ROOT"
  printf -- '- repo.md: `%s`\n' "$REPO_MD"
  printf -- '- Write the PoC to: `%s/poc.<ext>` (one file only)\n' "$poc_dir"
  if [[ -n "$hints_path" && -f "$hints_path" ]]; then
    printf -- '- Per-CWE hint rubric: `%s`\n' "$hints_path"
  fi
  if [[ -n "$target_lang" ]]; then
    printf -- '- Target language: `%s`\n' "$target_lang"
  fi
  printf '\n'
  if [[ -f "$finding_path" ]]; then
    printf '## Embedded finding\n\n```markdown\n'
    cat "$finding_path"
    printf '\n```\n\n'
  fi
  if [[ -f "$slice_file" ]]; then
    printf '## Embedded slice JSON\n\n```json\n'
    cat "$slice_file"
    printf '\n```\n\n'
  fi
  if [[ -n "$hints_path" && -f "$hints_path" ]]; then
    printf '## Embedded hint rubric\n\n```markdown\n'
    cat "$hints_path"
    printf '\n```\n'
  fi
}

# Optional per-CWE hint rubric / target-language overrides are picked up
# from env once at startup (still set by the Python driver), but the
# values are baked into each prompt rather than referenced by name.
HINTS_PATH="${AI_CODESCAN_HINTS_PATH:-}"
TARGET_LANG="${AI_CODESCAN_TARGET_LANG:-}"

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

  if ! render_prompt "$finding" "$slice_file" "$poc_dir" "$HINTS_PATH" "$TARGET_LANG" | invoke_llm; then
    echo "warning: $finding_id PoC author failed" >&2
    continue
  fi
  touch "$done_marker"
done
