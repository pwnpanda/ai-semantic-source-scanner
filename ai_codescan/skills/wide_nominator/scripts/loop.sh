#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="${AI_CODESCAN_RUN_DIR:?missing AI_CODESCAN_RUN_DIR}"
SKILL_DIR="${AI_CODESCAN_SKILL_DIR:?missing AI_CODESCAN_SKILL_DIR}"
LLM_CMD="${AI_CODESCAN_LLM_CMD:-}"
QUEUE="$RUN_DIR/queue.jsonl"
NOMS="$RUN_DIR/nominations.md"
PROMPT="$SKILL_DIR/prompts/nominator.md"

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
  # Reads the prompt from stdin and invokes either the wrapper script or
  # falls back to `claude -p` for backward compat.
  if [[ -n "$LLM_CMD" ]]; then
    "$LLM_CMD"
  else
    local prompt
    prompt="$(cat -)"
    claude -p "$prompt"
  fi
}

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  candidate_id=$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])')
  done_marker="$RUN_DIR/.done/${candidate_id}"
  if [[ -f "$done_marker" ]]; then
    continue
  fi
  mkdir -p "$RUN_DIR/.done"
  AI_CODESCAN_CANDIDATE="$line" \
    AI_CODESCAN_REPO_MD="$RUN_DIR/inputs/repo.md" \
    AI_CODESCAN_ENTRYPOINTS_MD="$RUN_DIR/inputs/entrypoints.md" \
    invoke_llm < "$PROMPT" || {
      echo "warning: candidate $candidate_id failed" >&2
      continue
    }
  touch "$done_marker"
done < "$QUEUE"
