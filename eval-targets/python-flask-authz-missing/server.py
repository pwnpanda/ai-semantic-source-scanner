from flask import Flask, request

app = Flask(__name__)

# Mock database
RESOURCES = {
    "1": {"owner": "user1", "data": "secret1"},
    "2": {"owner": "user2", "data": "secret2"},
}

@app.route("/resource/<id>", methods=["DELETE"])
def delete_resource(id):
    # VULNERABLE: Missing ownership check (BOLA/IDOR)
    # VULNERABLE: Missing authn/authz on state-changing operation
    if id in RESOURCES:
        del RESOURCES[id]
        return "Deleted", 200
    return "Not found", 404

if __name__ == "__main__":
    app.run()
