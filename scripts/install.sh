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

first_line_with_timeout() {
  # first_line_with_timeout <seconds> <command> [args...]
  local seconds="$1" output rc first_line
  shift
  if output="$(probe_first_line_with_timeout "$seconds" "$@")"; then
    printf '%s' "$output"
    return 0
  fi
  rc=$?
  if [[ "$rc" == "124" ]]; then
    printf 'present (version timed out)'
  else
    printf '%s' "${output:-present}"
  fi
}

probe_first_line_with_timeout() {
  # probe_first_line_with_timeout <seconds> <command> [args...]
  local seconds="$1" output rc first_line
  shift
  if command -v timeout >/dev/null 2>&1; then
    if output="$(timeout "${seconds}s" "$@" 2>&1)"; then
      rc=0
    else
      rc=$?
    fi
  else
    if output="$("$@" 2>&1)"; then
      rc=0
    else
      rc=$?
    fi
  fi
  first_line="${output%%$'\n'*}"
  printf '%s' "${first_line:-present}"
  return "$rc"
}

ask_yes_no() {
  local prompt="$1" default="$2" reply normalized
  if ! interactive; then
    [[ "$default" == "y" ]]; return $?
  fi
  local hint="[y/N]"; [[ "$default" == "y" ]] && hint="[Y/n]"
  printf '%s %s ' "$prompt" "$hint" >&2
  read -r reply || reply=""
  reply="${reply:-$default}"
  normalized="${reply,,}"
  [[ "$normalized" == "y" || "$normalized" == "yes" ]]
}

normalize_choice() {
  # normalize_choice <value> <default> <choice1> <choice2> ...
  local value="$1" default="$2"; shift 2
  local choices=("$@") normalized i c

  value="${value:-$default}"
  normalized="${value,,}"

  if [[ "$normalized" =~ ^[0-9]+$ ]]; then
    if (( normalized >= 1 && normalized <= ${#choices[@]} )); then
      printf '%s' "${choices[$((normalized - 1))]}"; return 0
    fi
    return 1
  fi

  for c in "${choices[@]}"; do
    if [[ "$c" == "$normalized" || "${c:0:1}" == "$normalized" ]]; then
      printf '%s' "$c"; return 0
    fi
  done
  return 1
}

ask_choice() {
  # ask_choice <prompt> <default> <choice1> <choice2> ...
  local prompt="$1" default="$2"; shift 2
  local choices=("$@") reply selected i
  if ! interactive; then
    printf '%s' "$default"; return 0
  fi
  printf '%s [%s]\n' "$prompt" "$(IFS=/; echo "${choices[*]}")" >&2
  for i in "${!choices[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "${choices[$i]}" >&2
  done
  printf '  default: %s > ' "$default" >&2
  read -r reply || reply=""
  if selected="$(normalize_choice "$reply" "$default" "${choices[@]}")"; then
    printf '%s' "$selected"; return 0
  fi
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
if [[ -d .venv ]]; then
  say "Python venv already exists; reusing .venv"
else
  uv venv >/dev/null
fi
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
  say "scip-typescript: $(first_line_with_timeout 5 scip-typescript --version)"
else
  say "Installing scip-typescript (npm global)"
  npm install -g @sourcegraph/scip-typescript
fi

# ---------------------------------------------------------------------------
# Auto-install Graphviz (`dot`) if missing
# ---------------------------------------------------------------------------
if command -v dot >/dev/null 2>&1; then
  say "graphviz: $(first_line_with_timeout 5 dot -V)"
else
  say "Installing graphviz (for visualize --fmt svg|png)"
  sys_install graphviz || warn "visualize will only emit DOT until graphviz is present"
fi

# ---------------------------------------------------------------------------
# Auto-install CodeQL if missing
# ---------------------------------------------------------------------------
if command -v codeql >/dev/null 2>&1; then
  say "codeql: $(first_line_with_timeout 5 codeql --version)"
else
  if ask_yes_no "Install CodeQL CLI 2.25+ (~600 MB)?" "y"; then
    CQ_DEST="$HOME/.local/share/codeql"
    mkdir -p "$CQ_DEST" "$HOME/.local/bin"
    say "Downloading codeql-linux64.zip from GitHub releases"
    curl -fsSL -o /tmp/codeql.zip "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip"
    unzip -q -o /tmp/codeql.zip -d "$CQ_DEST/.."
    rm -f /tmp/codeql.zip
    ln -sf "$CQ_DEST/codeql" "$HOME/.local/bin/codeql"
    say "codeql -> $(first_line_with_timeout 5 "$HOME"/.local/bin/codeql --version)"
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
elif ! RUNTIME="$(normalize_choice "$RUNTIME" "docker" docker podman none)"; then
  warn "unknown AICS_RUNTIME='${AICS_RUNTIME}'; using default 'docker'"
  RUNTIME="docker"
fi
case "$RUNTIME" in
  docker)
    if command -v docker >/dev/null 2>&1; then
      say "docker: $(first_line_with_timeout 5 docker --version)"
    else
      err "docker not on PATH; install Docker Desktop / docker-ce, then re-run"
      RUNTIME="none"; warn "downgrading to runtime=none"
    fi ;;
  podman)
    if command -v podman >/dev/null 2>&1; then
      say "podman: $(first_line_with_timeout 5 podman --version)"
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
# LLM CLIs — informational only, user picks
# ---------------------------------------------------------------------------
echo
status_check() {
  if command -v "$2" >/dev/null 2>&1; then
    printf '  %s[OK]%s    %-22s %s\n' "$GREEN" "$RESET" "$1" "($(first_line_with_timeout 5 "$2" --version))"
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
JOERN_DEST="${AICS_JOERN_DIR:-$HOME/.local/share/joern}"
JOERN_LINK_DIR="${AICS_JOERN_LINK_DIR:-$HOME/.local/bin}"
JOERN_VERSION="${AICS_JOERN_VERSION:-}"
if command -v joern >/dev/null 2>&1 && [[ "${AICS_REINSTALL_JOERN:-}" != "yes" ]]; then
  say "Joern already installed: $(first_line_with_timeout 8 joern --help)"
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
    command -v curl >/dev/null 2>&1 || { err "curl is required to install Joern"; exit 1; }
    command -v unzip >/dev/null 2>&1 || { err "unzip is required to install Joern"; exit 1; }

    JOERN_ZIP="$(mktemp /tmp/joern-cli.XXXXXX.zip)"
    if [[ -n "$JOERN_VERSION" ]]; then
      JOERN_URL="https://github.com/joernio/joern/releases/download/$JOERN_VERSION/joern-cli.zip"
    else
      JOERN_URL="https://github.com/joernio/joern/releases/latest/download/joern-cli.zip"
    fi

    if [[ -d "$JOERN_DEST/joern-cli" ]]; then
      if [[ "${AICS_REINSTALL_JOERN:-}" == "yes" ]] || ask_yes_no "Replace existing Joern install at $JOERN_DEST/joern-cli?" "n"; then
        rm -rf "$JOERN_DEST/joern-cli"
      else
        say "Reusing existing Joern install at $JOERN_DEST/joern-cli"
      fi
    fi

    if [[ ! -d "$JOERN_DEST/joern-cli" ]]; then
      say "Downloading Joern from $JOERN_URL"
      if [[ -t 1 ]]; then
        curl -fL --retry 3 --retry-delay 2 --progress-bar -o "$JOERN_ZIP" "$JOERN_URL"
      else
        curl -fL --retry 3 --retry-delay 2 -o "$JOERN_ZIP" "$JOERN_URL"
      fi
      say "Validating Joern archive (this can take a minute)"
      unzip -tq "$JOERN_ZIP" >/dev/null || { err "downloaded Joern archive is not a valid zip"; exit 1; }
      say "Extracting Joern to $JOERN_DEST (this can take several minutes)"
      mkdir -p "$JOERN_DEST"
      unzip -q -o "$JOERN_ZIP" -d "$JOERN_DEST"
      say "Joern archive extracted"
    fi
    rm -f "$JOERN_ZIP"

    say "Linking Joern tools into $JOERN_LINK_DIR"
    mkdir -p "$JOERN_LINK_DIR"
    for exe in \
      joern joern-parse c2cpg.sh ghidra2cpg jssrc2cpg.sh javasrc2cpg \
      jimple2cpg kotlin2cpg php2cpg rubysrc2cpg pysrc2cpg joern-export \
      joern-flow joern-scan joern-slice; do
      [[ -e "$JOERN_DEST/joern-cli/$exe" ]] && ln -sf "$JOERN_DEST/joern-cli/$exe" "$JOERN_LINK_DIR/$exe"
    done

    JOERN_BIN="$JOERN_DEST/joern-cli/joern"
    JOERN_PARSE_BIN="$JOERN_DEST/joern-cli/joern-parse"
    [[ -x "$JOERN_BIN" ]] || { err "Joern binary missing after install: $JOERN_BIN"; exit 1; }
    [[ -x "$JOERN_PARSE_BIN" ]] || { err "joern-parse missing after install: $JOERN_PARSE_BIN"; exit 1; }

    say "Verifying Joern startup (can take up to 90 seconds)"
    if joern_status="$(probe_first_line_with_timeout 90 "$JOERN_BIN" --help)"; then
      say "Joern starts: $joern_status"
    else
      err "Joern installed, but startup check failed: $joern_status"
      exit 1
    fi
    if joern_parse_status="$(probe_first_line_with_timeout 90 "$JOERN_PARSE_BIN" --list-languages)"; then
      say "joern-parse works: $joern_parse_status"
    else
      err "Joern installed, but joern-parse check failed: $joern_parse_status"
      exit 1
    fi
    if ! command -v joern >/dev/null 2>&1; then
      warn "Joern installed, but \`joern\` is not on PATH; add $JOERN_LINK_DIR to PATH"
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
