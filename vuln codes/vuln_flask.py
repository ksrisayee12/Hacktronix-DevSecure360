# vuln_flask.py
# Run: pip install flask
from flask import Flask, request, jsonify
import sqlite3
import subprocess

app = Flask(__name__)

# Hardcoded secret (Bandit will flag)
API_KEY = "super-secret-key-123"

# Very small example DB initializer (for local testing)
def init_db():
    conn = sqlite3.connect("test.db")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.commit()
    conn.close()

@app.route("/user")
def get_user():
    # UNSAFE: vulnerable to SQL injection (string concat)
    user = request.args.get("name", "")
    conn = sqlite3.connect("test.db")
    # vulnerable query
    q = "SELECT id, name, email FROM users WHERE name = '%s'" % user
    cur = conn.execute(q)
    row = cur.fetchone()
    conn.close()
    if row:
        return jsonify({"id": row[0], "name": row[1], "email": row[2]})
    return jsonify({"error": "not found"}), 404

@app.route("/run")
def run_cmd():
    # UNSAFE: directly uses user input in shell command
    cmd = request.args.get("cmd", "echo hello")
    # shell injection vulnerability
    output = subprocess.check_output(cmd, shell=True, text=True)
    return jsonify({"out": output})

if __name__ == "__main__":
    init_db()
    app.run(port=5000, debug=True)
