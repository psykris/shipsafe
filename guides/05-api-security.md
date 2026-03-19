# Guide 05 — API Security

## What This Guide Covers

Common API security mistakes in AI-generated codebases: authentication on every
route, rate limiting, input validation, error handling that leaks internals, and
CORS misconfiguration.

---

## 1. Authenticate Every Route

Never rely on "security through obscurity" (e.g., a long random URL). Every
route that touches user data must verify identity.

```python
# Bad — no auth check
@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    return jsonify(User.query.get(user_id).to_dict())

# Good — require a valid session token
from functools import wraps

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        user = verify_jwt(token)          # raises on invalid/expired
        g.current_user = user
        return f(*args, **kwargs)
    return decorated

@app.route("/api/users/<int:user_id>")
@require_auth
def get_user(user_id):
    if g.current_user.id != user_id and not g.current_user.is_admin:
        abort(403)
    return jsonify(User.query.get_or_404(user_id).to_dict())
```

---

## 2. Rate Limit All Public Endpoints

Without rate limiting, your API is vulnerable to:

- Credential stuffing (automated login attempts)
- DoS via expensive endpoints
- Data scraping

```python
# Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app, default_limits=["200/day", "50/hour"])

@app.route("/api/login", methods=["POST"])
@limiter.limit("5/minute")   # strict limit on auth endpoints
def login():
    ...

@app.route("/api/search")
@limiter.limit("30/minute")
def search():
    ...
```

For AI endpoints specifically, set per-user token budgets (see guide 09).

---

## 3. Validate and Bound All Inputs

```python
from pydantic import BaseModel, constr, conint, validator

class CreateUserRequest(BaseModel):
    username: constr(min_length=3, max_length=30, pattern=r'^[a-zA-Z0-9_]+$')
    email: str
    age: conint(ge=13, le=120)

    @validator('email')
    def valid_email(cls, v):
        if '@' not in v or len(v) > 254:
            raise ValueError('Invalid email')
        return v.lower()

@app.route("/api/users", methods=["POST"])
@require_auth
def create_user():
    try:
        body = CreateUserRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 400
    ...
```

**Never** pass raw `request.json` or `request.args` directly to database queries,
shell commands, or LLM prompts.

---

## 4. Use Safe Error Responses

Stack traces, SQL errors, and file paths must never reach API consumers.

```python
# Bad — leaks internal details
@app.errorhandler(Exception)
def handle_error(e):
    return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500

# Good — opaque error with a correlation ID
import uuid, logging

logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    error_id = str(uuid.uuid4())[:8]
    logger.exception("Unhandled error [%s]", error_id)
    return jsonify({"error": "Internal server error", "id": error_id}), 500
```

---

## 5. Harden CORS

```python
# Bad — wildcard allows any origin (CFG003)
CORS(app, origins="*")

# Good — allowlist specific origins
from flask_cors import CORS

CORS(app, resources={
    r"/api/*": {
        "origins": ["https://app.yoursite.com", "https://www.yoursite.com"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
    }
})
```

---

## 6. Set Security Headers

Use `flask-talisman` or set headers manually:

```python
from flask_talisman import Talisman

Talisman(app,
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        "default-src": "'self'",
        "script-src": "'self'",
    },
    referrer_policy="strict-origin-when-cross-origin",
)
```

---

## Checklist

- [ ] Every data endpoint requires authentication
- [ ] Auth endpoints are rate-limited (5/min or stricter)
- [ ] All inputs validated with Pydantic or equivalent
- [ ] Error responses never expose stack traces or SQL errors
- [ ] CORS restricted to your specific domains
- [ ] Security headers (CSP, HSTS, X-Frame-Options) enabled

## Related Rules

| Rule | What it catches |
|------|-----------------|
| CFG003 | CORS wildcard origin |
| DEP001 | Debug routes in production |
| DEP006 | Missing security headers |
| AUTH003 | Insecure cookie configuration |
| AUTH004 | Disabled CSRF protection |
