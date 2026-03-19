# Intentionally vulnerable: service binding to all network interfaces
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    # VULNERABLE: binding to 0.0.0.0 exposes service on all network interfaces
    app.run(host="0.0.0.0", port=8000, debug=False)
