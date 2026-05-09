"""Tiny Flask app with a deliberate SQL-injection vulnerability.

Used as a fixture for ai-codescan's Python pipeline; the handler concatenates
a request parameter directly into a SQL string, which CodeQL/Semgrep/Joern
should all flag as CWE-89.
"""

from __future__ import annotations

import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


def _db() -> sqlite3.Connection:
    return sqlite3.connect(":memory:")


@app.route("/u")
def get_user() -> object:
    user_id = request.args.get("id", "")
    # CWE-89: user_id flows unparameterised into the SQL string.
    sql = "SELECT id, name FROM users WHERE id=" + user_id
    cur = _db().cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    return jsonify(rows)


if __name__ == "__main__":
    app.run(port=3000)
