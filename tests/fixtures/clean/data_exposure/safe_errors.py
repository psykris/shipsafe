# Correct: generic error responses
from flask import jsonify

@app.errorhandler(500)
def handle_error(e):
    return jsonify({"error": "Internal server error"}), 500
