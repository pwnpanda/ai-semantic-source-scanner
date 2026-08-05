from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/proxy")
def proxy():
    target_url = request.args.get("url")
    # VULNERABLE: Direct SSRF via user-controlled URL
    response = requests.get(target_url)
    return response.text

if __name__ == "__main__":
    app.run()
