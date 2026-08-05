from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    # SAFE: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    db.close()
    
    return str(user) if user else "Not found"

if __name__ == "__main__":
    app.run()
