# Guide 06 — Deployment Hardening

> **Who this is for:** You're about to deploy your app (or have already deployed it) and want to make sure your server, containers, and configuration don't expose unnecessary attack surface.

---

## DEP001 — Dockerfile Running as Root

### What's wrong

By default, Docker containers run as the `root` user. Root inside a container has broad permissions. If an attacker exploits a vulnerability in your application, they get a root shell — which makes container escape attacks easier and maximizes damage.

```dockerfile
# DANGEROUS — runs as root (default if USER is omitted)
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```

### The fix

```dockerfile
FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create a non-root user and switch to it
RUN addgroup --system appgroup && \
    adduser --system --ingroup appgroup --no-create-home appuser

USER appuser

EXPOSE 8000
CMD ["python", "app.py"]
```

**Or use a numeric UID** (more portable across registries):
```dockerfile
USER 1001
```

---

## DEP002 — Exposed Debug and Admin Routes

### What's wrong

Debug and admin endpoints expose internal application state. AI tools often scaffold these for development convenience and forget to remove or protect them.

```python
# DANGEROUS — these should not be publicly accessible
@app.route("/admin")
def admin():
    return jsonify({"users": User.query.all()})  # No auth!

@app.route("/debug")
def debug():
    return jsonify({"env": dict(os.environ)})  # Exposes secrets!
```

### The fix

For admin panels:
```python
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated

@app.route("/admin")
@login_required
@admin_required
def admin():
    return render_template("admin/dashboard.html")
```

For debug tools (Swagger, GraphQL explorer, etc.):
- Remove completely from production builds, OR
- Restrict to internal network / VPN only via your reverse proxy:
  ```nginx
  location /swagger {
    allow 10.0.0.0/8;  # Internal network only
    deny all;
  }
  ```

---

## DEP003 — Build Secrets in Dockerfile

### What's wrong

Secrets passed via `ENV` or `ARG` are **permanently baked into Docker image layers**. Even if you delete the variable in a later layer, `docker history` can reveal the value.

```dockerfile
# DANGEROUS — these values are visible in `docker history`
ENV DATABASE_PASSWORD=supersecretpassword
ARG API_KEY=hardcoded_key_1234567890
```

```bash
# Any attacker with image access can run:
docker history myimage:latest --no-trunc
# → Shows every ENV/ARG value ever set
```

### The fix

**Option 1: Docker BuildKit secrets (for build-time secrets)**
```dockerfile
# In Dockerfile:
RUN --mount=type=secret,id=npm_token \
    npm config set //registry.npmjs.org/:_authToken=$(cat /run/secrets/npm_token) \
    && npm install

# Build with:
# docker build --secret id=npm_token,src=$HOME/.npmrc .
```

**Option 2: Runtime environment variables (for app secrets)**
```dockerfile
# Dockerfile — no secrets here
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
USER 1001
CMD ["python", "app.py"]
```

```bash
# Pass secrets at runtime via environment file:
docker run --env-file .env myimage:latest

# Or with Docker Compose:
# services:
#   app:
#     env_file: .env
```

---

## DEP004 — Binding to All Interfaces (0.0.0.0)

### What's wrong

Binding to `0.0.0.0` means your app listens on every network interface — including public ones. Without a firewall, this directly exposes your app to the internet.

```python
# POTENTIALLY DANGEROUS in production without a firewall
app.run(host="0.0.0.0", port=8000)
```

### The fix

**For local development:** Bind to `127.0.0.1` (loopback only):
```python
app.run(host="127.0.0.1", port=8000)
```

**For production:** Use a reverse proxy (nginx, Caddy, Vercel, etc.) in front of your app. The app binds to `127.0.0.1`; the proxy handles public traffic:

```nginx
# nginx — handles public requests, proxies to localhost
server {
    listen 443 ssl;
    server_name myapp.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
    }
}
```

**Inside Docker containers:** `0.0.0.0` is often intentional (so the container's port can be mapped). Restrict external access using Docker's port publishing and cloud security groups instead.

---

## DEP005 — Exposed Source Maps

### What's wrong

Source maps let browsers show your original TypeScript/JSX source code when debugging minified bundles. In production, they expose:

- Your full application logic
- Variable names and function internals
- Comments (including security TODOs)
- Any secrets that accidentally ended up in your client-side code

```javascript
// webpack.config.js — DANGEROUS in production
module.exports = {
  devtool: 'source-map',  // Creates .js.map files alongside bundles
};
```

### The fix

```javascript
// webpack.config.js — separate dev and prod configs
const isProd = process.env.NODE_ENV === 'production';

module.exports = {
  devtool: isProd ? false : 'eval-source-map',
};
```

```bash
# React (Create React App):
GENERATE_SOURCEMAP=false npm run build

# Vue CLI (vue.config.js):
module.exports = {
  productionSourceMap: false,
};
```

**If you need source maps for error tracking** (e.g., Sentry), upload them privately:
```bash
# Upload to Sentry without serving them publicly
sentry-cli releases files VERSION upload-sourcemaps ./dist --rewrite
# Then delete the .map files from your public build
```

---

## DEP006 — Insecure Security Header Configuration

### What's wrong

HTTP security headers tell browsers how to handle your content. Misconfiguring them removes protection against common attacks.

```python
# DANGEROUS configurations:
response.headers["X-Frame-Options"] = "ALLOWALL"     # Enables clickjacking
response.headers["X-Content-Type-Options"] = "none"  # Enables MIME sniffing
response.headers["Strict-Transport-Security"] = "max-age=0"  # Disables HTTPS enforcement
```

### The fix

**Correct header values:**

| Header | Safe Value | Protects Against |
|--------|-----------|-----------------|
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME confusion attacks |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HTTP downgrade attacks |
| `Content-Security-Policy` | `default-src 'self'` | XSS, data injection |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referrer leakage |
| `Permissions-Policy` | `geolocation=(), microphone=()` | Feature abuse |

**The easy way — use a library:**

```bash
# Node.js / Express:
npm install helmet
```
```javascript
const helmet = require('helmet');
app.use(helmet()); // Sets all security headers with safe defaults
```

```bash
# Python / Django:
pip install django-csp django-security
```
```python
# settings.py
MIDDLEWARE = [
    'csp.middleware.CSPMiddleware',
    'django.middleware.security.SecurityMiddleware',
    # SecurityMiddleware sets X-Content-Type-Options, X-Frame-Options, HSTS
    ...
]
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
X_FRAME_OPTIONS = 'DENY'
```

**Verify your headers:** Visit [securityheaders.com](https://securityheaders.com) with your deployed URL to get an instant grade.

---

## Deployment Security Checklist

- [ ] Dockerfile has a `USER` directive (non-root user)
- [ ] No `ENV` or `ARG` with secrets in Dockerfile
- [ ] Admin and debug routes require authentication or are removed in production
- [ ] App binds to `127.0.0.1` behind a reverse proxy (or uses proper firewall rules for containers)
- [ ] Source maps are disabled in production builds
- [ ] Security headers are set (use `helmet` for Express, Django's `SecurityMiddleware` for Django)
- [ ] HTTPS is enforced with HSTS header
- [ ] Content Security Policy is configured
- [ ] Docker images are scanned for CVEs before deployment (use `docker scout` or Trivy)

---

*Back to: [Guide 02 — Authentication](02-authentication.md) | [Guide 04 — Input Validation](04-input-validation.md)*
