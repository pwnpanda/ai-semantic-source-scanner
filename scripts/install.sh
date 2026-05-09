#!/usr/bin/env bash
# ai-semantic-source-scanner installer.
# Idempotent. Run from the repo root.
#
# Goal: a single command sets up every dependency the scanner needs.
#
# Usage:
#   bash scripts/install.sh
#   AICS_NONINTERACTIVE=1 bash scripts/install.sh        # never prompt; defaults
#   AICS_INSTALL_JOERN=yes bash scripts/install.sh        # force-install Joern
#   AICS_INSTALL_JOERN=no  bash scripts/install.sh        # skip Joern
#   AICS_RUNTIME=podman    bash scripts/install.sh        # docker | podman | none
#   AICS_INSTALL_INTERACTSH=no bash scripts/install.sh    # skip interactsh
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
say()  { printf '%s==>%s %s\n' "$BOLD$GREEN" "$RESET" "$*"; }
warn() { printf '%s!! %s%s\n' "$BOLD$YELLOW" "$*" "$RESET" >&2; }
err()  { printf '%sxx %s%s\n' "$BOLD$RED"    "$*" "$RESET" >&2; }

interactive() { [[ "${AICS_NONINTERACTIVE:-}" != "1" ]] && [[ -t 0 ]]; }

ask_yes_no() {
  local prompt="$1" default="$2" reply
  if ! interactive; then
    [[ "$default" == "y" ]]; return $?
  fi
  local hint="[y/N]"; [[ "$default" == "y" ]] && hint="[Y/n]"
  read -r -p "$prompt $hint " reply || reply=""
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy]$ ]]
}

ask_choice() {
  # ask_choice <prompt> <default> <choice1> <choice2> ...
  local prompt="$1" default="$2"; shift 2
  local choices=("$@") reply
  if ! interactive; then
    printf '%s' "$default"; return 0
  fi
  printf '%s [%s]\n' "$prompt" "$(IFS=/; echo "${choices[*]}")"
  read -r -p "  default: $default > " reply || reply=""
  reply="${reply:-$default}"
  for c in "${choices[@]}"; do
    if [[ "$c" == "$reply" ]]; then printf '%s' "$c"; return 0; fi
  done
  warn "unknown choice '$reply'; using default '$default'"
  printf '%s' "$default"
}

OS_FAMILY="unknown"
if command -v apt-get >/dev/null 2>&1; then OS_FAMILY="debian"
elif command -v dnf >/dev/null 2>&1; then OS_FAMILY="fedora"
elif command -v pacman >/dev/null 2>&1; then OS_FAMILY="arch"
elif command -v brew >/dev/null 2>&1; then OS_FAMILY="brew"
fi

# Try to install a system package; print a hint if we can't run sudo.
sys_install() {
  local pkg="$1" cmd
  case "$OS_FAMILY" in
    debian) cmd="sudo apt-get install -y $pkg" ;;
    fedora) cmd="sudo dnf install -y $pkg" ;;
    arch)   cmd="sudo pacman -S --noconfirm $pkg" ;;
    brew)   cmd="brew install $pkg" ;;
    *)      err "no known package manager; install '$pkg' manually"; return 1 ;;
  esac
  if ask_yes_no "Run \`$cmd\`?" "y"; then
    eval "$cmd"
  else
    warn "skipped; install '$pkg' yourself"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Required tools
# ---------------------------------------------------------------------------
say "Checking required tools (uv, node, pnpm, git)"
need=()
for cmd in uv node pnpm git; do
  command -v "$cmd" >/dev/null 2>&1 || need+=("$cmd")
done
if (( ${#need[@]} )); then
  err "Missing: ${need[*]}"
  cat <<EOF
Install pointers:
  uv     -> https://docs.astral.sh/uv/getting-started/installation/  (curl -LsSf https://astral.sh/uv/install.sh | sh)
  node   -> https://nodejs.org   (>=22; or via nvm: \`nvm install 22\`)
  pnpm   -> corepack enable && corepack prepare pnpm@latest --activate
  git    -> your distro's package manager
EOF
  exit 1
fi
say "Required tools OK"

# ---------------------------------------------------------------------------
# Python venv + deps  (auto: uv handles everything)
# ---------------------------------------------------------------------------
say "Creating Python venv (.venv) and syncing deps"
uv venv >/dev/null
uv sync --all-groups --quiet
say "Python deps installed"

# ---------------------------------------------------------------------------
# Node worker deps
# ---------------------------------------------------------------------------
say "Installing Node worker deps (ai_codescan/ast/node_worker)"
( cd ai_codescan/ast/node_worker && pnpm install --silent )
say "Node worker ready"

# ---------------------------------------------------------------------------
# Auto-install scip-typescript via npm if missing
# ---------------------------------------------------------------------------
if command -v scip-typescript >/dev/null 2>&1; then
  say "scip-typescript: $(scip-typescript --version 2>&1 | head -1)"
else
  say "Installing scip-typescript (npm global)"
  npm install -g @sourcegraph/scip-typescript
fi

# ---------------------------------------------------------------------------
# Auto-install Graphviz (`dot`) if missing
# ---------------------------------------------------------------------------
if command -v dot >/dev/null 2>&1; then
  say "graphviz: $(dot -V 2>&1 | head -1)"
else
  say "Installing graphviz (for visualize --fmt svg|png)"
  sys_install graphviz || warn "visualize will only emit DOT until graphviz is present"
fi

# ---------------------------------------------------------------------------
# Auto-install CodeQL if missing
# ---------------------------------------------------------------------------
if command -v codeql >/dev/null 2>&1; then
  say "codeql: $(codeql --version 2>&1 | head -1)"
else
  if ask_yes_no "Install CodeQL CLI 2.25+ (~600 MB)?" "y"; then
    CQ_DEST="$HOME/.local/share/codeql"
    mkdir -p "$CQ_DEST" "$HOME/.local/bin"
    say "Downloading codeql-linux64.zip from GitHub releases"
    curl -fsSL -o /tmp/codeql.zip "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip"
    unzip -q -o /tmp/codeql.zip -d "$CQ_DEST/.."
    rm -f /tmp/codeql.zip
    ln -sf "$CQ_DEST/codeql" "$HOME/.local/bin/codeql"
    say "codeql -> $("$HOME"/.local/bin/codeql --version 2>&1 | head -1)"
    case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) warn "Add \$HOME/.local/bin to PATH" ;; esac
  fi
fi

# ---------------------------------------------------------------------------
# Container runtime: docker | podman | none
# ---------------------------------------------------------------------------
echo
echo "${BOLD}Container runtime${RESET} is used by the validator sandbox to run PoC scripts safely."
echo "  docker  - default; widely available, requires Docker Desktop or daemon"
echo "  podman  - rootless alternative, drop-in CLI compatible"
echo "  none    - no container; PoC validation is DISABLED, only PoC generation works"
RUNTIME="${AICS_RUNTIME:-}"
if [[ -z "$RUNTIME" ]]; then
  RUNTIME="$(ask_choice "Pick a runtime" "docker" docker podman none)"
fi
case "$RUNTIME" in
  docker)
    if command -v docker >/dev/null 2>&1; then
      say "docker: $(docker --version 2>&1 | head -1)"
    else
      err "docker not on PATH; install Docker Desktop / docker-ce, then re-run"
      RUNTIME="none"; warn "downgrading to runtime=none"
    fi ;;
  podman)
    if command -v podman >/dev/null 2>&1; then
      say "podman: $(podman --version 2>&1 | head -1)"
    else
      say "Installing podman"
      sys_install podman || { err "podman install failed"; RUNTIME="none"; warn "downgrading to runtime=none"; }
    fi ;;
  none) warn "runtime=none — \`ai-codescan validate\` will refuse to run PoCs" ;;
esac

# Persist the choice via the Python config helper.
say "Persisting runtime choice to ~/.config/ai-codescan/config.yaml"
uv run python - <<PY
from ai_codescan.user_config import UserConfig, save
save(UserConfig(container_runtime="${RUNTIME}", poc_language_preference="auto"))
print("saved")
PY

# ---------------------------------------------------------------------------
# interactsh (out-of-band callback for validator verdict v2)
# ---------------------------------------------------------------------------
echo
if command -v interactsh-client >/dev/null 2>&1; then
  say "interactsh-client: $(interactsh-client -version 2>&1 | head -1)"
else
  if [[ "${AICS_INSTALL_INTERACTSH:-}" == "no" ]]; then
    warn "Skipping interactsh (env override)"
  elif ask_yes_no "Install interactsh-client (Project Discovery; out-of-band callback proof)?" "y"; then
    if command -v go >/dev/null 2>&1; then
      say "Installing via \`go install\`"
      GOBIN="$HOME/.local/bin" go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    else
      say "go missing; downloading prebuilt release"
      INT_DEST="$HOME/.local/share/interactsh"
      mkdir -p "$INT_DEST" "$HOME/.local/bin"
      latest=$(curl -fsSL https://api.github.com/repos/projectdiscovery/interactsh/releases/latest | grep -oE '"tag_name": "v[0-9.]+"' | head -1 | cut -d'"' -f4)
      asset_url=$(curl -fsSL "https://api.github.com/repos/projectdiscovery/interactsh/releases/tags/$latest" \
        | grep -oE '"browser_download_url": "[^"]*linux_amd64.zip"' | head -1 | cut -d'"' -f4)
      [[ -n "$asset_url" ]] || { err "no linux_amd64 release asset"; exit 1; }
      curl -fsSL -o /tmp/interactsh.zip "$asset_url"
      unzip -q -o /tmp/interactsh.zip -d "$INT_DEST"
      rm -f /tmp/interactsh.zip
      ln -sf "$INT_DEST/interactsh-client" "$HOME/.local/bin/interactsh-client"
    fi
    if command -v interactsh-client >/dev/null 2>&1; then
      say "interactsh-client installed"
    else
      warn "install attempted but binary not on PATH; check $HOME/.local/bin"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# LLM CLIs — informational only, user picks
# ---------------------------------------------------------------------------
echo
status_check() {
  if command -v "$2" >/dev/null 2>&1; then
    printf '  %s[OK]%s    %-22s %s\n' "$GREEN" "$RESET" "$1" "($($2 --version 2>&1 | head -1))"
  else
    printf '  %s[MISSING]%s %-15s %s\n' "$YELLOW" "$RESET" "$1" "$3"
  fi
}
say "LLM CLI availability (at least one is required at runtime)"
status_check "claude"  claude  "https://claude.com/code"
status_check "gemini"  gemini  "https://github.com/google-gemini/gemini-cli (npm i -g @google/gemini-cli)"
status_check "codex"   codex   "https://github.com/openai/codex (npm i -g @openai/codex)"

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
      warn "Joern installer ran but \`joern\` is not on PATH; add \$HOME/.local/bin to PATH"
    fi
  else
    say "Skipped Joern. Re-run with \`AICS_INSTALL_JOERN=yes bash scripts/install.sh\` to pick up later."
  fi
fi

# ---------------------------------------------------------------------------
# Skill install
# ---------------------------------------------------------------------------
echo
if command -v claude >/dev/null 2>&1 && ask_yes_no "Install bundled Claude Code skills into ~/.claude/skills/?" "y"; then
  uv run ai-codescan install-skills
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
echo
say "Verifying install with the test suite"
uv run pytest -q

echo
say "Install complete."
echo "Next:"
echo "  uv run ai-codescan --help"
echo "  uv run ai-codescan run /path/to/target --target-bug-class injection --yes"
