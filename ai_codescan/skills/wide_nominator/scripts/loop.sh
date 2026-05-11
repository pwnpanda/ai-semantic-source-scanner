#!/usr/bin/env bash
# Drive the wide-nominator skill loop.
#
# Two design choices keep this robust against agentic-LLM sandboxes:
#
# 1. Per-iteration inputs (candidate JSON, absolute paths, embedded
#    repo.md / entrypoints.md) are inlined into the prompt body so the
#    LLM never has to read environment variables.
# 2. The LLM prints its nomination block to stdout bracketed by sentinels
#    instead of writing nominations.md directly. We capture stdout,
#    extract the block, and append it ourselves — this sidesteps every
#    file-modifying-tool permission prompt the LLM CLI might raise on
#    paths outside the user's project.
set -euo pipefail

RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
QUEUE="$RUN_DIR/queue.jsonl"
NOMS="$RUN_DIR/nominations.md"
PROMPT="$SKILL_DIR/prompts/nominator.md"
REPO_MD="$RUN_DIR/inputs/repo.md"
ENTRY_MD="$RUN_DIR/inputs/entrypoints.md"

if [[ ! -f "$NOMS" ]]; then
  cat > "$NOMS" <<'EOF'
# Nominations

## Stream A — Pre-traced (CodeQL flows ready for triage)

## Stream B — AI-discovered candidates (no static flow exists; semantic concern)

## Stream C — Proposed CodeQL model extensions

EOF
fi

if [[ ! -f "$QUEUE" ]]; then
  echo "no queue at $QUEUE" >&2
  exit 1
fi

invoke_llm() {
  if [[ -n "$LLM_CMD" ]]; then
    "$LLM_CMD"
  else
    local prompt
    prompt="$(cat -)"
    claude -p "$prompt"
  fi
}

render_prompt() {
  local candidate="$1"
  cat "$PROMPT"
  printf '\n\n---\n\n## This iteration\n\n'
  printf 'Candidate JSON (classify and nominate this one):\n\n'
  printf '```json\n%s\n```\n\n' "$candidate"
  printf 'Reference paths (for Read/Grep — do not write):\n\n'
  printf -- '- Repo overview: `%s`\n' "$REPO_MD"
  printf -- '- Entrypoints: `%s`\n' "$ENTRY_MD"
  printf -- '- Source snapshot root: `%s/inputs/source/`\n\n' "$RUN_DIR"
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

append_nomination_from_stdout() {
  # Pull the first ``<<<AI_CODESCAN_NOMINATION:STREAM=X>>>`` … ``<<<...:END>>>``
  # block out of the LLM's stdout and append the body under the right
  # Stream header in $NOMS. Returns non-zero if no block was found so the
  # caller can warn but keep iterating.
  local llm_out="$1"
  python3 - "$llm_out" "$NOMS" <<'PY'
import re
import sys
from pathlib import Path

raw = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
noms_path = Path(sys.argv[2])

start_re = re.compile(r"<<<AI_CODESCAN_NOMINATION:STREAM=([ABC])>>>", re.MULTILINE)
end_re = re.compile(r"<<<AI_CODESCAN_NOMINATION:END>>>", re.MULTILINE)
m_start = start_re.search(raw)
m_end = end_re.search(raw, m_start.end()) if m_start else None
if not m_start or not m_end:
    print("no nomination block found in LLM output", file=sys.stderr)
    sys.exit(2)

stream = m_start.group(1)
body = raw[m_start.end():m_end.start()].strip("\n")
header_re = re.compile(rf"^## Stream {stream} —.*$", re.MULTILINE)

contents = noms_path.read_text(encoding="utf-8")
hm = header_re.search(contents)
if not hm:
    print(f"no Stream {stream} header in {noms_path}", file=sys.stderr)
    sys.exit(3)

# Insert the body immediately after the header line + blank line.
insert_at = contents.find("\n", hm.end()) + 1
if contents[insert_at:insert_at + 1] == "\n":
    insert_at += 1
new_contents = contents[:insert_at] + body + "\n\n" + contents[insert_at:]
noms_path.write_text(new_contents, encoding="utf-8")
PY
}

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  candidate_id=$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])')
  done_marker="$RUN_DIR/.done/${candidate_id}"
  if [[ -f "$done_marker" ]]; then
    continue
  fi
  mkdir -p "$RUN_DIR/.done"
  iter_log="$RUN_DIR/.done/${candidate_id}.stdout"
  if ! render_prompt "$line" | invoke_llm > "$iter_log"; then
    echo "warning: candidate $candidate_id failed (llm error)" >&2
    continue
  fi
  if ! append_nomination_from_stdout "$iter_log"; then
    echo "warning: candidate $candidate_id produced no nomination block" >&2
    continue
  fi
  touch "$done_marker"
done < "$QUEUE"
