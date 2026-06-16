from flask import Flask, request
import sqlite3
import subprocess
import os
import bcrypt
import ast

app = Flask(__name__)

SECRET_KEY = os.getenv("SECRET_KEY", "default-secret")


# =========================
# LOGIN (SQL Injection fixed + bcrypt)
# =========================
@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}

    username = data.get("username")
    password = data.get("password")

    # Validation inputs
    if not username or not password:
        return {"error": "Missing fields"}, 400

    if len(username) > 50:
        return {"error": "Invalid username"}, 400

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        query = "SELECT password FROM users WHERE username=?"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result:
            stored_hash = result[0]

            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                return {"status": "success", "user": username}

        return {"status": "error", "message": "Invalid credentials"}

    except Exception:
        return {"error": "Server error"}, 500


# =========================
# PING (Command Injection fixed)
# =========================
@app.route("/ping", methods=["POST"])
def ping():
    data = request.json or {}
    host = data.get("host", "")

    if not host:
        return {"error": "Missing host"}, 400

    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", host]
        )
        return {"output": output.decode()}
    except Exception:
        return {"error": "Ping failed"}, 500


# =========================
# COMPUTE (eval removed / safer)
# =========================
@app.route("/compute", methods=["POST"])
def compute():
    data = request.json or {}
    expression = data.get("expression", "1+1")

    try:
        # safe evaluation only (no code execution)
        result = ast.literal_eval(expression)
        return {"result": result}
    except Exception:
        return {"error": "Invalid expression"}, 400


# =========================
# HASH (bcrypt instead of MD5)
# =========================
@app.route("/hash", methods=["POST"])
def hash_password():
    data = request.json or {}
    pwd = data.get("password", "admin")

    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())

    return {"hash": hashed.decode()}


# =========================
# READ FILE (basic protection)
# =========================
@app.route("/readfile", methods=["POST"])
def readfile():
    data = request.json or {}
    filename = data.get("filename", "test.txt")

    # simple restriction (prevent path traversal)
    if ".." in filename or "/" in filename:
        return {"error": "Invalid filename"}, 400

    try:
        with open(filename, "r") as f:
            content = f.read()

        return {"content": content}

    except Exception:
        return {"error": "File not found"}, 404


# =========================
# DEBUG (removed sensitive info)
# =========================
@app.route("/debug", methods=["GET"])
def debug():
    return {
        "debug": False,
        "message": "Debug disabled for security"
    }


# =========================
# HELLO
# =========================
@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Secure DevSecOps API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)