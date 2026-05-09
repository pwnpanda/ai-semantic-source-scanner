"""Tiny FastAPI app with a deliberate CWE-22 path-traversal.

Used as a fixture for ai-codescan's Python pipeline; the handler reads a
file path from the query string and opens it without normalisation, which
CodeQL/Semgrep/Joern should all flag.
"""

from __future__ import annotations

from fastapi import FastAPI, Query

app = FastAPI()


@app.get("/files")
def read_file(name: str = Query(..., description="filename to read")) -> dict[str, str]:
    # CWE-22: ``name`` is concatenated into the path and opened directly.
    full_path = "/var/data/" + name
    with open(full_path, encoding="utf-8") as fh:
        body = fh.read()
    return {"path": full_path, "body": body}
