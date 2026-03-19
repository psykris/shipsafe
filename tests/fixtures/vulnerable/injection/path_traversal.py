# Intentionally vulnerable: path traversal
import os
from flask import request, send_file


def read_file():
    # VULNERABLE: user input used directly in open()
    filename = request.args.get("file")
    with open(request.args.get("path"), "r") as f:
        return f.read()


def serve_file():
    # VULNERABLE: send_file with user-controlled path
    path = request.args.get("filename")
    return send_file(request.args.get("filename"))


def get_log():
    # VULNERABLE: os.path.join with unsanitized input allows traversal
    log_name = request.args.get("log")
    full_path = os.path.join("/var/logs", request.args.get("log"))
    with open(full_path) as f:
        return f.read()
