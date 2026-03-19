# Intentionally vulnerable: stack trace in error response
from flask import jsonify
import traceback

@app.errorhandler(500)
def handle_error(e):
    return jsonify({
        "error": str(e),
        "traceback": traceback.format_exc(),
        "debug_info": repr(e.__dict__)
    }), 500
