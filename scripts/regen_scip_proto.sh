#!/usr/bin/env bash
set -euo pipefail
PROTO_URL="https://raw.githubusercontent.com/sourcegraph/scip/v0.7.1/scip.proto"
OUT_DIR="ai_codescan/third_party"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
curl -fsSL "$PROTO_URL" -o "$TMPDIR/scip.proto"
uv run python -m grpc_tools.protoc \
  --proto_path="$TMPDIR" \
  --python_out="$OUT_DIR" \
  "$TMPDIR/scip.proto"
echo "regenerated $OUT_DIR/scip_pb2.py"
