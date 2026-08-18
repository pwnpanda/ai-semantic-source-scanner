"""Positive Python receiver variants for Phase 21 NoSQL and ReDoS rules."""

import re

from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
mongo_users = MongoClient("mongodb://example.invalid").app.users


@app.post("/search")
def search() -> dict[str, int | bool]:
    filter_document = request.json
    pattern = request.args["pattern"]
    records = list(mongo_users.find(filter_document))
    matcher = re.compile(pattern)
    return {"count": len(records), "matches": matcher.search("probe") is not None}


if __name__ == "__main__":
    app.run(port=9003)
