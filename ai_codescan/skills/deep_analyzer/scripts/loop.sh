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
SOURCE_ROOT="${AI_CODESCAN_SOURCE_ROOT:-$RUN_DIR/../../source}"

[[ -f "$QUEUE" ]] || { echo "no $QUEUE" >&2; exit 1; }
mkdir -p "$RUN_DIR/findings" "$RUN_DIR/.done-analyze"

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
  local nomination="$1"
  local evidence_file="$2"
  local finding_id="$3"
  cat "$PROMPT"
  printf '\n\n---\n\n## This iteration\n\n'
  printf 'Nomination id: `%s`\n' "$nom_id"
  printf 'Finding id: `%s`\n\n' "$finding_id"
  printf 'Nomination block (from `nominations.md`):\n\n```\n%s\n```\n\n' "$nomination"
  printf 'Reference paths (for Read/Grep — do not write):\n\n'
  printf -- '- Evidence bundle JSON: `%s`\n' "$evidence_file"
  printf -- '- Source snapshot root: `%s`\n\n' "$SOURCE_ROOT"
  if [[ -f "$evidence_file" ]]; then
    printf '## Embedded evidence bundle JSON\n\n```json\n'
    cat "$evidence_file"
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

total=$(grep -cE '^- \[ \] N-' "$QUEUE" || true)
done_count=$(find "$RUN_DIR/.done-analyze" -maxdepth 1 -type f ! -name '*.stdout' 2>/dev/null | wc -l | tr -d ' ')
echo "[analyze] queue: $total nominations ($done_count already done)" >&2

idx=0
while IFS= read -r line; do
  if [[ ! "$line" =~ ^-\ \[\ \]\ (N-[A-Za-z0-9_-]+)\ \|\ ([^|]+)\ \|\ ([^|]+)\ \| ]]; then
    continue
  fi
  idx=$((idx + 1))
  nom_id="${BASH_REMATCH[1]}"
  done="$RUN_DIR/.done-analyze/${nom_id}"
  if [[ -f "$done" ]]; then
    echo "[analyze] $idx/$total $nom_id … skip (already done)" >&2
    continue
  fi
  finding_id="F-${nom_id#N-}"
  finding_path="$RUN_DIR/findings/${finding_id}.md"
  evidence_file="$RUN_DIR/bundles/${nom_id}.json"
  if [[ ! -f "$evidence_file" ]]; then
    evidence_file="$RUN_DIR/slices/${nom_id}.json"
  fi
  if [[ ! -f "$evidence_file" ]]; then
    echo "[analyze] $idx/$total $nom_id … skip (no evidence bundle)" >&2
    continue
  fi
  printf '[analyze] %d/%d %s … ' "$idx" "$total" "$nom_id" >&2
  iter_log="$RUN_DIR/.done-analyze/${nom_id}.stdout"
  start_ts=$(date +%s)
  if ! render_prompt "$line" "$evidence_file" "$finding_id" | invoke_llm > "$iter_log"; then
    echo "FAIL (llm error)" >&2
    continue
  fi
  if ! write_finding_from_stdout "$iter_log" "$finding_path"; then
    elapsed=$(( $(date +%s) - start_ts ))
    echo "FAIL no block (${elapsed}s)" >&2
    continue
  fi
  status=$(grep -E '^status:' "$finding_path" | head -1 | awk '{print $2}')
  elapsed=$(( $(date +%s) - start_ts ))
  echo "ok → ${status:-unknown} (${elapsed}s)" >&2
  touch "$done"
done < "$QUEUE"
echo "[analyze] done" >&2
