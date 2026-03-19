# Intentionally vulnerable: hardcoded authentication credentials
import requests

# VULNERABLE: credentials in a tuple literal
auth = ("admin", "password123")
response = requests.get("https://api.internal.com/data", auth=auth)

# VULNERABLE: Basic auth header with base64-encoded credentials
headers = {
    "Authorization": "Basic YWRtaW46cGFzc3dvcmQxMjM="
}
resp = requests.get("https://api.internal.com/admin", headers=headers)
