from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "World")
    # VULNERABLE: Direct reflected XSS
    template = f"<h1>Hello {name}</h1>"
    return render_template_string(template)

if __name__ == "__main__":
    app.run()
