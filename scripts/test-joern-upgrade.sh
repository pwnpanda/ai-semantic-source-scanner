#!/usr/bin/env bash
# test-joern-upgrade.sh — try a candidate Joern version without committing it.
#
# Downloads the target Joern release into an isolated dir, points the eval
# pipeline at it via env vars, and runs the full eval suite. The pinned
# JOERN_PINNED_VERSION in scripts/install.sh is the source of truth; this
# script ONLY validates that a candidate version still passes the eval
# suite. It does NOT install the candidate as the system Joern.
#
# Usage:
#   scripts/test-joern-upgrade.sh v4.0.540
#
# Exit codes:
#   0  candidate Joern passed the full eval suite
#   1  candidate failed (eval regressions; see /tmp/aics-eval-joern-<ver>/)
#   2  bad usage / download / unzip failure
#
# After a successful run, bump JOERN_PINNED_VERSION in scripts/install.sh
# and commit. Re-running scripts/install.sh on each dev box picks up the
# new pin.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <joern-version-tag>  (e.g. v4.0.540)" >&2
  exit 2
fi
CANDIDATE="$1"
SCRATCH="$(mktemp -d /tmp/aics-joern-upgrade.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

JOERN_URL="https://github.com/joernio/joern/releases/download/${CANDIDATE}/joern-cli.zip"
JOERN_ZIP="$SCRATCH/joern-cli.zip"
echo "[upgrade-test] downloading ${CANDIDATE} from ${JOERN_URL}"
curl -fL --retry 3 --retry-delay 2 -o "$JOERN_ZIP" "$JOERN_URL" || {
  echo "[upgrade-test] download failed — is ${CANDIDATE} a valid Joern release tag?" >&2
  exit 2
}

echo "[upgrade-test] unzipping into ${SCRATCH}"
unzip -q -o "$JOERN_ZIP" -d "$SCRATCH"
CANDIDATE_BIN="$SCRATCH/joern-cli"
if [[ ! -x "$CANDIDATE_BIN/joern" ]]; then
  echo "[upgrade-test] unexpected archive layout: no joern at $CANDIDATE_BIN/joern" >&2
  exit 2
fi

# Prepend the candidate Joern bin dir to PATH so the eval pipeline picks
# it up instead of the system-pinned version. We deliberately do NOT touch
# the system install — this is purely a validation pass.
EVAL_OUT="/tmp/aics-eval-joern-${CANDIDATE//\//_}"
rm -rf "$EVAL_OUT"
echo "[upgrade-test] running full eval against candidate Joern (output: $EVAL_OUT)"
PATH="$CANDIDATE_BIN:$PATH" \
  .venv/bin/python -m ai_codescan eval run --targets eval-targets --out "$EVAL_OUT" \
  || true

# Eval exit code is informational; rely on result counts instead.
PASS=$(grep -c '"status": "pass"' "$EVAL_OUT/results.jsonl" 2>/dev/null || echo 0)
FAIL=$(grep -cE '"status": "(false_positive|miss|error|partial)"' "$EVAL_OUT/results.jsonl" 2>/dev/null || echo 0)
TOTAL=$((PASS + FAIL))

echo
echo "[upgrade-test] ===== summary ====="
echo "[upgrade-test] candidate:  $CANDIDATE"
echo "[upgrade-test] pass:       $PASS / $TOTAL"
echo "[upgrade-test] non-pass:   $FAIL / $TOTAL"
echo "[upgrade-test] full results: $EVAL_OUT/results.jsonl"

if [[ "$FAIL" -ne 0 ]] || [[ "$TOTAL" -eq 0 ]]; then
  echo "[upgrade-test] FAIL — do NOT bump JOERN_PINNED_VERSION" >&2
  exit 1
fi

echo "[upgrade-test] OK — safe to bump JOERN_PINNED_VERSION to $CANDIDATE"
echo "[upgrade-test] next: edit scripts/install.sh, change JOERN_PINNED_VERSION, commit."
