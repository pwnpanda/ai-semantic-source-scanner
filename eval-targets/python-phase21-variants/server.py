"""Positive Python receiver variants for Phase 20 and 21 rules."""

import logging
import re

from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
mongo_client = MongoClient("mongodb://example.invalid")
db = mongo_client.app
logger = logging.getLogger(__name__)


@app.post("/search")
def search() -> dict[str, int | bool]:
    filter_document = request.json
    pattern = request.args["pattern"]
    authorization = request.headers["Authorization"]
    records = list(db.users.find(filter_document))
    archived = list(db["archived_users"].find(filter_document))
    matcher = re.compile(pattern)
    logger.error(authorization)
    return {
        "count": len(records) + len(archived),
        "matches": matcher.search("probe") is not None,
    }


if __name__ == "__main__":
    app.run(port=9003)
