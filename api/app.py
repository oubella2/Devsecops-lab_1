@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json() or {}

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"status": "error", "message": "Missing username or password"}, 400

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        )

        result = cursor.fetchone()
        conn.close()

        if result:
            return {"status": "success", "user": username}

        return {"status": "error", "message": "Invalid credentials"}, 401

    except Exception:
        return {"status": "error", "message": "Internal server error"}, 500