# SAFE: proper authentication patterns
import os
import bcrypt
import jwt
from flask import request, jsonify

# SAFE: JWT secret loaded from environment
JWT_SECRET = os.environ.get("JWT_SECRET_KEY")

# SAFE: session cookies secured
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True

# SAFE: CSRF protection enabled
WTF_CSRF_ENABLED = True
CSRF_ENABLED = True

# SAFE: restrictive default permissions
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]
}


def login():
    password = request.json.get("password")
    stored_hash = get_hash_from_db()

    # SAFE: bcrypt comparison, not == with a literal
    if bcrypt.checkpw(password.encode(), stored_hash):
        payload = {"user_id": 1}
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401


# SAFE: auth loaded from environment, not hardcoded
auth = (os.environ["SVC_USERNAME"], os.environ["SVC_PASSWORD"])
