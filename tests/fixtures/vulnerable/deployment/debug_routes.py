# Intentionally vulnerable: exposed debug/admin routes without auth
from flask import Flask, jsonify

app = Flask(__name__)


# VULNERABLE: /admin route registered without authentication middleware
@app.route("/admin")
def admin_panel():
    return jsonify({"users": [], "config": {}, "db_stats": {}})


# VULNERABLE: debug endpoint exposes internal state
@app.route("/debug")
def debug_info():
    import sys
    return jsonify({"python": sys.version, "env": dict(os.environ)})


# Express-style — VULNERABLE
# app.get('/graphql', graphqlHandler)
# app.get('/swagger', swaggerUI)
