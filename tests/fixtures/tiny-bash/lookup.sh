#!/usr/bin/env bash
# Tiny shell script with a deliberate CWE-78 command-injection.
#
# Used as a fixture for ai-codescan's Bash pipeline; the script reads a
# user-supplied argument and passes it to ``eval`` without quoting,
# which Semgrep should flag.

set -euo pipefail

main() {
    local user_input="$1"
    # CWE-78: $user_input flows unquoted into eval.
    eval "echo result: $user_input"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
