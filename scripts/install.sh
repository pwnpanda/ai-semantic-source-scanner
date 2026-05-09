#!/usr/bin/env bash
# ai-semantic-source-scanner installer.
# Idempotent. Run from the repo root.
#
# Usage:
#   bash scripts/install.sh           # interactive
#   AICS_NONINTERACTIVE=1 bash scripts/install.sh   # never prompt; defaults
#   AICS_INSTALL_JOERN=yes bash scripts/install.sh  # force-install Joern
#   AICS_INSTALL_JOERN=no  bash scripts/install.sh  # skip Joern install
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" == "" ]]; then
  GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  GREEN=""; YELLOW=""; RED=""; BOLD=""; RESET=""
fi
say()    { printf '%s==>%s %s\n' "$BOLD$GREEN" "$RESET" "$*"; }
warn()   { printf '%s!! %s%s\n'   "$BOLD$YELLOW" "$*"      "$RESET" >&2; }
err()    { printf '%sxx %s%s\n'   "$BOLD$RED"    "$*"      "$RESET" >&2; }

ask_yes_no() {
  # ask_yes_no <prompt> <default y|n>
  local prompt="$1" default="$2" reply
  if [[ "${AICS_NONINTERACTIVE:-}" == "1" ]] || [[ ! -t 0 ]]; then
    [[ "$default" == "y" ]]; return $?
  fi
  local hint="[y/N]"; [[ "$default" == "y" ]] && hint="[Y/n]"
  read -r -p "$prompt $hint " reply || reply=""
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
say "Checking prerequisites"
need=()
for cmd in uv node pnpm git; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    need+=("$cmd")
  fi
done
if (( ${#need[@]} )); then
  err "Missing required tools: ${need[*]}"
  cat <<EOF
Install pointers:
  uv     -> https://docs.astral.sh/uv/getting-started/installation/
  node   -> https://nodejs.org   (>=22; or via nvm)
  pnpm   -> npm i -g pnpm        (or via corepack: corepack enable && corepack prepare pnpm@latest --activate)
  git    -> your distro's package manager
EOF
  exit 1
fi
say "Prerequisites OK (uv, node, pnpm, git)"

# ---------------------------------------------------------------------------
# Python venv + deps
# ---------------------------------------------------------------------------
say "Creating Python venv (.venv) and installing dependencies"
uv venv >/dev/null
uv sync --all-groups --quiet
say "Python deps installed"

# ---------------------------------------------------------------------------
# Node worker deps (ts-morph + parse5 + tree-sitter)
# ---------------------------------------------------------------------------
say "Installing Node worker dependencies (ai_codescan/ast/node_worker)"
( cd ai_codescan/ast/node_worker && pnpm install --silent )
say "Node worker ready"

# ---------------------------------------------------------------------------
# Optional system tools — report status, don't block
# ---------------------------------------------------------------------------
say "Checking optional integrations"
status() {
  # status <label> <command> <reason-if-missing>
  if command -v "$2" >/dev/null 2>&1; then
    printf '  %s[OK]%s    %-22s %s\n' "$GREEN" "$RESET" "$1" "($($2 --version 2>&1 | head -1))"
  else
    printf '  %s[MISSING]%s %-15s %s\n' "$YELLOW" "$RESET" "$1" "$3"
  fi
}
status "codeql"            codeql            "default static engine; install CodeQL CLI 2.25+ from github.com/github/codeql-cli-binaries"
status "scip-typescript"   scip-typescript   "needed for cross-file symbol IDs; npm i -g @sourcegraph/scip-typescript"
status "docker"            docker            "needed for sandbox PoC validation (validate command)"
status "dot (graphviz)"    dot               "needed for visualize --fmt svg|png; apt-get install graphviz"
status "claude"            claude            "default LLM CLI; one of claude|gemini|codex must be on PATH"
status "gemini"            gemini            "alternative LLM CLI"
status "codex"             codex             "alternative LLM CLI"

# ---------------------------------------------------------------------------
# Joern — opt-in heavyweight install
# ---------------------------------------------------------------------------
echo
if command -v joern >/dev/null 2>&1; then
  say "Joern already installed: $(joern --version 2>/dev/null | head -1 || echo present)"
elif [[ "${AICS_INSTALL_JOERN:-}" == "no" ]]; then
  warn "Skipping Joern (AICS_INSTALL_JOERN=no). Hybrid mode falls back to CodeQL + Semgrep."
else
  echo "${BOLD}Joern${RESET} extends \`--engine hybrid\` with a third static analyser."
  echo "  Download size: ~1.5 GB (JVM + Joern distribution)"
  echo "  Disk usage:    ~2 GB once unpacked"
  echo "  Required for:  more complete cross-file taint coverage on JS/TS, Java, Python, Go, Kotlin"
  echo "  Skippable:     yes — \`--engine codeql\` and \`--engine hybrid\` (CodeQL + Semgrep) work without it"
  echo
  if [[ "${AICS_INSTALL_JOERN:-}" == "yes" ]] || ask_yes_no "Install Joern now?" "n"; then
    say "Installing Joern via the official installer"
    curl -fsSL https://github.com/joernio/joern/releases/latest/download/joern-install.sh -o /tmp/joern-install.sh
    bash /tmp/joern-install.sh --version=latest --install-dir="$HOME/.local/share/joern" --link-dir="$HOME/.local/bin"
    rm -f /tmp/joern-install.sh
    if command -v joern >/dev/null 2>&1; then
      say "Joern installed: $(joern --version 2>/dev/null | head -1 || echo ok)"
    else
      warn "Joern installer ran but \`joern\` is not on PATH. Add ~/.local/bin to PATH or re-run."
    fi
  else
    say "Skipped Joern. You can install later with: AICS_INSTALL_JOERN=yes bash scripts/install.sh"
  fi
fi

# ---------------------------------------------------------------------------
# Skill install (Claude Code skills under ~/.claude/skills/)
# ---------------------------------------------------------------------------
echo
if command -v claude >/dev/null 2>&1; then
  if ask_yes_no "Install bundled Claude Code skills (wide_nominator, deep_analyzer, validator, llm_heavy) into ~/.claude/skills/?" "y"; then
    uv run ai-codescan install-skills
  else
    say "Skipped skill install. Run \`uv run ai-codescan install-skills\` later if needed."
  fi
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
echo
say "Verifying install with the test suite"
uv run pytest -q || { err "Tests failed"; exit 1; }

echo
say "Install complete."
echo "Next: run \`uv run ai-codescan --help\` or \`uv run ai-codescan run /path/to/target --yes\`."
