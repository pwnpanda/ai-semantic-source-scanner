#!/usr/bin/env bash
# Drive the wide-nominator skill loop.
#
# Each candidate descriptor (one JSON-per-line in queue.jsonl) is appended
# to the static prompt template and piped into the configured LLM CLI.
# Inlining the candidate + absolute paths means the LLM never has to read
# environment variables to do its job — modern agentic CLIs (claude-code,
# codex) sandbox shell access and block ``printenv`` / parameter
# expansion, which used to leave the agent stranded with no inputs.
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
  # Read the rendered prompt from stdin and invoke either the wrapper
  # script or ``claude -p`` directly. The wrapper script is preferred —
  # it handles per-provider argv differences and was set up by Python.
  if [[ -n "$LLM_CMD" ]]; then
    "$LLM_CMD"
  else
    local prompt
    prompt="$(cat -)"
    claude -p "$prompt"
  fi
}

render_prompt() {
  # Append the candidate JSON, the absolute paths of every input file,
  # and (when small) the contents of repo.md / entrypoints.md directly
  # to the prompt body. The LLM no longer needs env-var access.
  local candidate="$1"
  cat "$PROMPT"
  printf '\n\n---\n\n## This iteration\n\n'
  printf 'Candidate JSON (the descriptor you must classify and nominate):\n\n'
  printf '```json\n%s\n```\n\n' "$candidate"
  printf 'Files you must use:\n\n'
  printf -- '- Append your nomination block to: `%s`\n' "$NOMS"
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

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  candidate_id=$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])')
  done_marker="$RUN_DIR/.done/${candidate_id}"
  if [[ -f "$done_marker" ]]; then
    continue
  fi
  mkdir -p "$RUN_DIR/.done"
  if ! render_prompt "$line" | invoke_llm; then
    echo "warning: candidate $candidate_id failed" >&2
    continue
  fi
  touch "$done_marker"
done < "$QUEUE"
