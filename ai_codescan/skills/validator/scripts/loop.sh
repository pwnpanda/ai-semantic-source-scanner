#!/usr/bin/env bash
# Validator skill loop. Same robust-against-sandbox protocol as the
# other skills: inputs inlined into the prompt, PoC source extracted
# from sentinel-bracketed stdout.
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
  local hints_path="$3"
  local target_lang="$4"
  cat "$PROMPT"
  printf '\n\n---\n\n## This iteration\n\n'
  printf 'Reference paths (for Read/Grep — do not write):\n\n'
  printf -- '- Finding: `%s`\n' "$finding_path"
  printf -- '- Slice JSON: `%s`\n' "$slice_file"
  printf -- '- Source snapshot root: `%s`\n' "$SOURCE_ROOT"
  printf -- '- repo.md: `%s`\n' "$REPO_MD"
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

write_poc_from_stdout() {
  local llm_out="$1"
  local poc_dir="$2"
  python3 - "$llm_out" "$poc_dir" <<'PY'
import re
import sys
from pathlib import Path

allowed = {"py", "js", "php", "rb", "go", "sh"}
raw = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
poc_dir = Path(sys.argv[2])
start = re.search(r"<<<AI_CODESCAN_POC:EXT=([a-z]+)>>>", raw)
end = re.search(r"<<<AI_CODESCAN_POC:END>>>", raw[start.end():]) if start else None
if not start or not end:
    print("no PoC block in LLM output", file=sys.stderr)
    sys.exit(2)
ext = start.group(1)
if ext not in allowed:
    print(f"unsupported PoC extension: {ext}", file=sys.stderr)
    sys.exit(3)
body = raw[start.end():start.end() + end.start()].strip("\n")
out_path = poc_dir / f"poc.{ext}"
out_path.write_text(body + "\n", encoding="utf-8")
print(out_path)
PY
}

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

  iter_log="$RUN_DIR/.done-validate/${finding_id}.stdout"
  if ! render_prompt "$finding" "$slice_file" "$HINTS_PATH" "$TARGET_LANG" \
       | invoke_llm > "$iter_log"; then
    echo "warning: $finding_id PoC author failed (llm error)" >&2
    continue
  fi
  if ! write_poc_from_stdout "$iter_log" "$poc_dir" >/dev/null; then
    echo "warning: $finding_id produced no PoC block" >&2
    continue
  fi
  touch "$done_marker"
done
