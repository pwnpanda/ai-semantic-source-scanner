"""Vulnerable Flask SSRF target with TRANSITIVE alias of the HTTP client.

Phase 4 type-aware receiver test: a single-step alias chain
    client = httpx.Client()
    api    = client
    api.get(url)
must still produce a CWE-918 finding. The Phase 3 assignment-walk only
caught direct constructor assignments; the Phase 4 typeFullName scan and
fixed-point alias resolution in ``joern_queries.sc`` close the gap.
"""

import httpx
from flask import Flask, request

app = Flask(__name__)

client = httpx.Client()
api = client


@app.route("/proxy")
def proxy():
    url = request.args.get("url", "")
    response = api.get(url)
    return response.text


if __name__ == "__main__":
    app.run()
