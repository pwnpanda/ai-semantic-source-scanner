#!/usr/bin/env bash
set -euo pipefail

aics_item_fingerprint() {
  local payload="$1"
  shift
  AICS_ITEM_PAYLOAD="$payload" python3 -c '
import hashlib
import os
import sys
from pathlib import Path

digest = hashlib.sha256()
digest.update(os.environ.get("AICS_LLM_CONTEXT", "").encode())
digest.update(b"\0")
digest.update(os.environ["AICS_ITEM_PAYLOAD"].encode())
digest.update(b"\0")
for raw_path in sys.argv[1:]:
    path = Path(raw_path)
    digest.update(raw_path.encode())
    digest.update(b"\0")
    if path.is_file() and not path.is_symlink():
        digest.update(path.read_bytes())
    else:
        digest.update(b"missing")
    digest.update(b"\0")
print(digest.hexdigest())
' _ "$@"
}
