#!/usr/bin/env bash
# Drive the deep-analyzer skill loop. Same protocol as wide_nominator:
# inputs are inlined into the prompt, and the LLM emits its output via
# sentinels on stdout so we don't depend on file-modifying-tool
# permissions.
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
  cat "$PROMPT"
  printf '\n\n---\n\n## This iteration\n\n'
  printf 'Nomination block (from `nominations.md`):\n\n```\n%s\n```\n\n' "$nomination"
  printf 'Reference paths (for Read/Grep — do not write):\n\n'
  printf -- '- Slice JSON: `%s`\n' "$slice_file"
  printf -- '- Source snapshot root: `%s`\n\n' "$SOURCE_ROOT"
  if [[ -f "$slice_file" ]]; then
    printf '## Embedded slice JSON\n\n```json\n'
    cat "$slice_file"
    printf '\n```\n'
  fi
}

write_finding_from_stdout() {
  local llm_out="$1"
  local finding_path="$2"
  python3 - "$llm_out" "$finding_path" <<'PY'
import re
import sys
from pathlib import Path

raw = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
out_path = Path(sys.argv[2])
start = re.search(r"<<<AI_CODESCAN_FINDING:STATUS=([a-z_]+)>>>", raw)
end = re.search(r"<<<AI_CODESCAN_FINDING:END>>>", raw[start.end():]) if start else None
if not start or not end:
    print("no finding block in LLM output", file=sys.stderr)
    sys.exit(2)
body = raw[start.end():start.end() + end.start()].strip("\n")
out_path.write_text(body + "\n", encoding="utf-8")
PY
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
  iter_log="$RUN_DIR/.done-analyze/${nom_id}.stdout"
  if ! render_prompt "$line" "$slice_file" | invoke_llm > "$iter_log"; then
    echo "warning: $nom_id failed (llm error)" >&2
    continue
  fi
  if ! write_finding_from_stdout "$iter_log" "$finding_path"; then
    echo "warning: $nom_id produced no finding block" >&2
    continue
  fi
  touch "$done"
done < "$QUEUE"
