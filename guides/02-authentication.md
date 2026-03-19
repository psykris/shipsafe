# Guide 02 — Authentication Done Right

> **Who this is for:** You've built a login system with AI help and want to make sure it actually keeps attackers out. This guide explains the most common authentication mistakes and exactly how to fix them.

---

## The Lock Analogy

Authentication is your front door lock. A hardcoded password is like writing the combination on a sticky note stuck to the door. A JWT secret in your source code is like giving every contractor who worked on your building a master key and never changing the locks. These aren't theoretical risks — they're how real apps get broken into.

---

## AUTH001 — Hardcoded Password Comparison

### What's wrong

```python
# DANGEROUS — never do this
if password == "admin123":
    grant_access()
```

This stores your password in plaintext directly in your source code. Anyone who reads the code — a contractor, a disgruntled employee, or anyone who finds your public GitHub repo — has your password.

### Why it's worse than it sounds

- The password can never be rotated without a code deployment
- If you use the same password anywhere else, all those accounts are now at risk
- Git history preserves this forever even after you delete the line

### The fix

```python
import bcrypt

# When creating a user (store this hash in your database):
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# When checking login:
if bcrypt.checkpw(submitted_password.encode('utf-8'), stored_hash):
    grant_access()
```

**Framework shortcuts:**
- **Django:** `make_password()` and `check_password()` — Django handles this for you
- **Flask:** Use `flask-bcrypt` or `werkzeug.security.generate_password_hash()`
- **Express:** Use the `bcrypt` npm package

---

## AUTH002 — JWT with Hardcoded Secret

### What's wrong

```python
# DANGEROUS — the secret is in your source code
token = jwt.encode(payload, "my-secret-key", algorithm="HS256")
decoded = jwt.decode(token, "my-secret-key", algorithms=["HS256"])
```

A JWT (JSON Web Token) is a signed credential your server gives to users after login. The signature is created using a secret key. If an attacker knows your secret key, they can forge tokens for any user — including admins.

### The fix

```python
import os
import jwt

# Load from environment — never hardcode
JWT_SECRET = os.environ["JWT_SECRET_KEY"]

# Sign tokens
token = jwt.encode({"user_id": user.id}, JWT_SECRET, algorithm="HS256")

# Verify tokens
decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```

**Generate a strong secret:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Add this to your `.env` file:
```
JWT_SECRET_KEY=<paste the output here>
```

Add `.env` to `.gitignore` so it never gets committed.

---

## AUTH003 — Insecure Cookie and Session Configuration

### What's wrong

```python
# DANGEROUS — Django settings
SESSION_COOKIE_SECURE = False    # Cookie sent over plain HTTP
SESSION_COOKIE_HTTPONLY = False  # JavaScript can read your session cookie
```

Without `secure`, your session cookie is sent over unencrypted HTTP connections. A network attacker (on the same coffee shop WiFi, for example) can intercept it and impersonate the user.

Without `httpOnly`, a cross-site scripting (XSS) attack can steal the cookie using `document.cookie`.

### The fix

```python
# Django settings.py — production values
SESSION_COOKIE_SECURE = True     # Only send over HTTPS
SESSION_COOKIE_HTTPONLY = True   # Block JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax' # Mitigate CSRF

CSRF_COOKIE_SECURE = True
```

```javascript
// Express.js
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,    // HTTPS only
    httpOnly: true,  // No JS access
    sameSite: 'lax', // CSRF protection
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  }
}));
```

---

## AUTH004 — Disabled CSRF Protection

### What's wrong

```python
# DANGEROUS — removes CSRF protection from this view
@csrf_exempt
def transfer_funds(request):
    ...
```

CSRF (Cross-Site Request Forgery) is an attack where a malicious website tricks your logged-in users into submitting actions without their knowledge. Disabling CSRF protection enables attackers to make your users unknowingly transfer funds, change passwords, or delete data.

### The fix

**Django:** Remove `@csrf_exempt`. It's there by default — don't disable it.
```python
# SAFE — no decorator, CSRF middleware active
def transfer_funds(request):
    ...
```

**Flask-WTF:**
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
# WTF_CSRF_ENABLED = True  ← this is the default, don't change it
```

**Express:**
```javascript
const csrf = require('csurf');
app.use(csrf({ cookie: true }));
```

---

## AUTH005 — Hardcoded Authentication Credentials

### What's wrong

```python
# DANGEROUS — credentials embedded in code
auth = ("admin", "password123")
response = requests.get("https://api.internal.com/data", auth=auth)

# Also dangerous — Basic auth header with base64 value
headers = {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="}
```

These credentials are visible to every developer who has access to the code, every CI/CD log, and anyone who finds your repository. Base64 encoding is NOT encryption — it's trivially reversible.

### The fix

```python
import os

auth = (
    os.environ["SERVICE_USERNAME"],
    os.environ["SERVICE_PASSWORD"],
)
response = requests.get("https://api.internal.com/data", auth=auth)
```

---

## AUTH006 — Overly Permissive Default Permissions

### What's wrong

```python
# DANGEROUS — any unauthenticated request can access all API endpoints
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"]
}

class SensitiveDataView(APIView):
    permission_classes = []  # DANGEROUS — no access control at all
```

The principle of least privilege says: deny by default, allow explicitly. Starting with `AllowAny` and working backwards means you'll inevitably forget to add auth to some endpoint.

### The fix

```python
# Django REST Framework — restrictive by default
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ]
}

# Explicitly loosen only for public endpoints
from rest_framework.permissions import AllowAny

class PublicHealthCheckView(APIView):
    permission_classes = [AllowAny]  # Intentionally public

    def get(self, request):
        return Response({"status": "ok"})
```

---

## Checklist Before You Deploy Auth

- [ ] Passwords are hashed with bcrypt, argon2, or scrypt (never MD5 or SHA1)
- [ ] JWT secrets are loaded from environment variables, not hardcoded
- [ ] Session cookies have `secure=True` and `httpOnly=True`
- [ ] CSRF protection is enabled on all state-changing endpoints
- [ ] Default permissions require authentication (not `AllowAny`)
- [ ] Auth credentials for external services come from environment variables
- [ ] Login endpoints have rate limiting (see `guide/12-cost-security.md`)

---

*Next: [Guide 03 — Authorization and Access Control](03-authorization.md)*
