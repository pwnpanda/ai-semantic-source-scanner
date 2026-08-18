"""Safe receiver and static-argument near-misses for Python Phase 21 rules."""

import re

from flask import Flask, request


class SearchService:
    """Application search that does not interpret Mongo operators."""

    def find_one(self, value: object) -> object:
        return value


class Validator:
    """Application validator that does not compile a regular expression."""

    def compile(self, value: str) -> str:
        return value


app = Flask(__name__)
search_service = SearchService()
validator = Validator()
identifier = re.compile(r"^[a-z0-9_-]{1,64}$")


@app.post("/search")
def search() -> dict[str, bool]:
    payload = request.json
    pattern = request.args["pattern"]
    found = search_service.find_one(payload)
    compiled = validator.compile(pattern)
    return {"found": bool(found), "valid": bool(compiled) and identifier.fullmatch("probe")}


if __name__ == "__main__":
    app.run(port=9004)
