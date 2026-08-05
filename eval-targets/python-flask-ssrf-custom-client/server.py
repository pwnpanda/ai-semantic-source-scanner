"""Vulnerable Flask SSRF target using a custom HTTP-client wrapper.

Phase 5 end-to-end proof: `apiv2_fetch` is not in the bundled Joern SSRF
model — without the extension JSON, this scan produces no CWE-918 finding.
With ``aics-joern-extension-packs.json`` shipped alongside this target (the
eval harness copies it into the repo cache before Joern runs), Joern picks
up the additional ``apiv2_fetch`` sink pattern and the SSRF flow fires.
"""

from flask import Flask, request

app = Flask(__name__)


def apiv2_fetch(url: str) -> bytes:
    """Internal wrapper around the org's HTTP client. No allowlist."""
    import urllib.request  # noqa: PLC0415 — kept local for the test fixture

    return urllib.request.urlopen(url).read()


@app.route("/proxy")
def proxy():
    url = request.args.get("url", "")
    payload = apiv2_fetch(url)
    return payload


if __name__ == "__main__":
    app.run()
