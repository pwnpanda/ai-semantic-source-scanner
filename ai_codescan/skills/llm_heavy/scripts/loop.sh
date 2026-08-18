#!/usr/bin/env bash
# LLM-heavy walker driver. Same protocol as the other skills: inputs
# inlined into the prompt, output extracted from sentinel-bracketed
# stdout. No reliance on file-modifying-tool permissions.
# Markdown backticks are intentional literals in single-quoted printf formats.
# shellcheck disable=SC2016
set -euo pipefail
RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
PROMPT="$SKILL_DIR/prompts/walker.md"
OUT="$RUN_DIR/llm_heavy_flows.jsonl"
SOURCE_ROOT="${AI_CODESCAN_SOURCE_ROOT:?missing AI_CODESCAN_SOURCE_ROOT}"
REPO_MD="$RUN_DIR/inputs/repo.md"
ENTRY_MD="$RUN_DIR/inputs/entrypoints.md"
TARGET_BUG_CLASSES="${AI_CODESCAN_TARGET_BUG_CLASSES:-}"

: >"$OUT"

invoke_llm() {
  # Rate limits surface as a non-zero exit from the provider CLI. Callers
  # treat that as a permanent per-item failure and move on, so a throttle
  # part-way through a long queue silently burns every remaining item.
  # Back off and retry instead; only a persistent failure is fatal.
  #
  # stdin is consumed by the first attempt, so buffer the prompt to replay it.
  local prompt_file attempt delay rc
  prompt_file="$(mktemp)"
  cat - >"$prompt_file"
  delay="${AI_CODESCAN_LLM_RETRY_DELAY:-60}"
  rc=1
  for attempt in $(seq 1 "${AI_CODESCAN_LLM_RETRIES:-5}"); do
    if [[ -n "$LLM_CMD" ]]; then
      "$LLM_CMD" <"$prompt_file" && rc=0
    else
      claude -p "$(cat "$prompt_file")" && rc=0
    fi
    [[ "$rc" -eq 0 ]] && break
    printf 'llm attempt %d failed; retrying in %ds … ' "$attempt" "$delay" >&2
    sleep "$delay"
    delay=$((delay * 2))
  done
  rm -f "$prompt_file"
  return "$rc"
}

render_prompt() {
  cat "$PROMPT"
  printf '\n\n---\n\n## This run\n\n'
  printf 'Reference paths (for Read/Grep — do not write):\n\n'
  printf -- '- Source snapshot root: `%s`\n' "$SOURCE_ROOT"
  printf -- '- Repo overview: `%s`\n' "$REPO_MD"
  printf -- '- Entrypoints inventory (start here): `%s`\n' "$ENTRY_MD"
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

write_flows_from_stdout() {
  local llm_out="$1"
  python3 - "$llm_out" "$OUT" <<'PY'
import re
import sys
from pathlib import Path

raw = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
out_path = Path(sys.argv[2])
start = re.search(r"<<<AI_CODESCAN_FLOWS:BEGIN>>>", raw)
end = re.search(r"<<<AI_CODESCAN_FLOWS:END>>>", raw[start.end():]) if start else None
if not start or not end:
    print("no flows block in LLM output", file=sys.stderr)
    sys.exit(2)
body = raw[start.end():start.end() + end.start()].strip("\n")
# Preserve every non-empty protocol line so Python ingestion can reject
# malformed or prose-contaminated output instead of silently caching it.
lines = [ln for ln in body.splitlines() if ln.strip()]
out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
PY
}

echo "[llm-heavy] walking source tree (single LLM pass; this can take minutes)" >&2
iter_log="$RUN_DIR/.llm_heavy.stdout"
start_ts=$(date +%s)
if ! render_prompt | invoke_llm >"$iter_log"; then
  echo "[llm-heavy] FAIL (llm error)" >&2
  exit 1
fi
if ! write_flows_from_stdout "$iter_log"; then
  echo "[llm-heavy] FAIL no flows block" >&2
  exit 1
fi
elapsed=$(($(date +%s) - start_ts))
count=$(wc -l <"$OUT" 2>/dev/null | tr -d ' ')
echo "[llm-heavy] done: ${count:-0} flows in ${elapsed}s" >&2
