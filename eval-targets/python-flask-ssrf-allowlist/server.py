"""Safe Flask SSRF target: validates the request URL host against an allowlist.

Negative eval target for the broadened Python SSRF sink pattern (Phase 2).
The `requests.get` sink still fires under recall-first (Invariant 2), but the
`ssrf.host-allowlist` mitigation in scoring should demote the candidate.
"""

from urllib.parse import urlparse

import requests
from flask import Flask, request

app = Flask(__name__)

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}


@app.route("/proxy")
def proxy():
    target_url = request.args.get("url", "")
    parsed = urlparse(target_url)
    if parsed.hostname not in ALLOWED_HOSTS:
        return ("host not allowed", 400)
    response = requests.get(target_url, timeout=5)
    return response.text


if __name__ == "__main__":
    app.run()
