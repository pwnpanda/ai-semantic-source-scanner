"""Phase 20 NEGATIVE (Recall-First Invariant 5) — the hardened counterpart
to python-flask-xxe.

Same source and the same parse call, but the parser is explicitly configured
to refuse entity resolution, DTD loading, and network access. The candidate
may still surface (Invariant 2: mitigations demote, never drop) but must not
be an expected finding.
"""

from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse_xml():
    body = request.data
    # SAFE: entities are not resolved, the DTD is not loaded, and the parser
    # is forbidden from reaching the network.
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
    doc = etree.fromstring(body, parser)
    return etree.tostring(doc)
