#!/usr/bin/env bash
set -euo pipefail
proto_url="https://raw.githubusercontent.com/scip-code/scip/v0.9.0/scip.proto"
out_dir="ai_codescan/third_party"
tmp_dir=$(mktemp -d)
cleanup() {
  rm -f "$tmp_dir/scip.proto"
  rmdir "$tmp_dir"
}
trap cleanup EXIT
curl -fsSL "$proto_url" -o "$tmp_dir/scip.proto"
uv run python -m grpc_tools.protoc \
  --proto_path="$tmp_dir" \
  --python_out="$out_dir" \
  --pyi_out="$out_dir" \
  "$tmp_dir/scip.proto"
# grpc_tools models protobuf enums with a runtime metaclass that ty cannot reconcile with int.
sed -i \
  '/metaclass=_enum_type_wrapper.EnumTypeWrapper):$/s/$/  # ty: ignore[conflicting-metaclass]/' \
  "$out_dir/scip_pb2.pyi"
printf 'regenerated %s/scip_pb2.py and scip_pb2.pyi\n' "$out_dir"
