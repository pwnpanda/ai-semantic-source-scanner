"""Vulnerable Flask SSRF target where the HTTP client is an aliased instance.

Phase 3 type-aware receiver test: ``http_client = httpx.Client()`` followed by
``http_client.get(url)`` must still be matched as a CWE-918 sink even though
the variable name (``http_client``) is not the literal module name
(``httpx``/``requests``/etc.) the receiver regex hard-codes. The type-aware
AST walk in ``joern_queries.sc`` collects ``http_client`` from the
constructor assignment and allows it as a valid SSRF receiver.
"""

import httpx
from flask import Flask, request

app = Flask(__name__)

http_client = httpx.Client()


@app.route("/proxy")
def proxy():
    url = request.args.get("url", "")
    response = http_client.get(url)
    return response.text


if __name__ == "__main__":
    app.run()
