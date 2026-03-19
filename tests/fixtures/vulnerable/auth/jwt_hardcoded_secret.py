# Intentionally vulnerable: JWT with hardcoded secret
import jwt

PAYLOAD = {"user_id": 1, "role": "admin"}

# VULNERABLE: hardcoded signing secret
token = jwt.encode(PAYLOAD, "my-super-secret-key", algorithm="HS256")

# VULNERABLE: hardcoded secret in decode
decoded = jwt.decode(token, "my-super-secret-key", algorithms=["HS256"])

# VULNERABLE: secret assigned as hardcoded string
JWT_SECRET = "hardcoded-jwt-secret-do-not-use"
