# Intentionally vulnerable: insecure security header configuration
from flask import Flask, make_response

app = Flask(__name__)


@app.after_request
def add_headers(response):
    # VULNERABLE: X-Frame-Options set to ALLOWALL (enables clickjacking)
    response.headers["X-Frame-Options"] = "ALLOWALL"

    # VULNERABLE: disables MIME-type sniffing protection
    response.headers["X-Content-Type-Options"] = "none"

    # VULNERABLE: HSTS disabled with max-age=0
    response.headers["Strict-Transport-Security"] = "max-age=0"

    return response
