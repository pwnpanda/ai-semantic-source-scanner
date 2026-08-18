"""Phase 20 positive — XXE (CWE-611).

Source: request.data (raw attacker-controlled XML body).
Sink: lxml.etree.fromstring with a parser that resolves external entities.

POSTing

    <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>

discloses the file back in the response.
"""

from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse_xml():
    body = request.data
    # VULNERABLE: resolve_entities defaults to True and no_network is not set,
    # so SYSTEM entities are fetched (local file read + SSRF).
    parser = etree.XMLParser(resolve_entities=True)
    doc = etree.fromstring(body, parser)
    return etree.tostring(doc)
