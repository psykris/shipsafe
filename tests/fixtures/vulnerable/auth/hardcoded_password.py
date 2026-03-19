# Intentionally vulnerable: hardcoded password comparison
from flask import request, jsonify


def login():
    username = request.json.get("username")
    password = request.json.get("password")

    # VULNERABLE: comparing against a hardcoded plaintext password
    if password == "admin123":
        return jsonify({"status": "ok"})

    # Also vulnerable — reversed order
    if "supersecret" == passwd:
        return jsonify({"status": "ok"})

    return jsonify({"status": "unauthorized"}), 401
