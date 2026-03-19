# SAFE: routes with proper auth and no debug endpoints in production
from flask import Flask, jsonify
from functools import wraps

app = Flask(__name__)


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Proper authentication check
        token = get_token_from_request()
        if not verify_admin_token(token):
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


# SAFE: /users is not an admin/debug endpoint
@app.route("/api/users")
def list_users():
    return jsonify({"users": []})


# SAFE: 0.0.0.0 is NOT used; binding to localhost
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
