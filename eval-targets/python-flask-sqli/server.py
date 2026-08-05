from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    # VULNERABLE: String concatenation for SQL query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    db.close()
    
    return str(user) if user else "Not found"

if __name__ == "__main__":
    app.run()
