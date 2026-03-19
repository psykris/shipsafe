"""Authentication and authorization rules for ShipSafe.

Detects hardcoded password comparisons, JWT secrets, insecure session
configuration, disabled CSRF protection, hardcoded auth credentials,
and overly permissive default permissions.

Every pattern is a class-level constant so you can audit the full
catalogue with a single grep:

    grep -A5 "patterns = \\[" src/shipsafe/rules/auth.py

Design invariants
-----------------
- Patterns live on the class, never hidden inside methods.
- Matched values are **always** redacted before they appear in output.
- Every fix includes concrete, copy-pasteable remediation steps.
"""

import re

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule


# ── AUTH001  HardcodedPasswordComparison ─────────────────────────────


class HardcodedPasswordComparison(Rule):
    """Detect plaintext password comparisons in source code."""

    id = "AUTH001"
    name = "Hardcoded password comparison"
    severity = Severity.CRITICAL
    description = (
        "A password is compared directly against a hardcoded string literal. "
        "This means the password is stored in plaintext in source code, "
        "visible to anyone with repository access. Plaintext passwords "
        "cannot be rotated without a code change and are trivially "
        "extracted by attackers."
    )
    fix = (
        "Use proper password hashing instead of plaintext comparison:\n"
        "  import bcrypt\n"
        "  # When storing the password:\n"
        "  hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n"
        "  # When verifying:\n"
        "  if bcrypt.checkpw(password.encode(), stored_hash):\n"
        "      grant_access()\n"
        "Alternatives: argon2-cffi, passlib, or Django's make_password()."
    )
    guide_url = "guides/02-authentication.md"
    owasp_id = "A07:2021"
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r'(?:password|passwd|pwd)\s*(?:==|!=)\s*["\'][^"\']+["\']',
        r'["\'][^"\']+["\']\s*(?:==|!=)\s*(?:password|passwd|pwd)\b',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        """Mask the hardcoded password value in the comparison."""
        # Replace every quoted string value on this line
        return re.sub(r'(["\'])[^"\']+\1', r'\1[REDACTED]\1', line)


# ── AUTH002  JWTHardcodedSecret ──────────────────────────────────────


class JWTHardcodedSecret(Rule):
    """Detect JWT operations using hardcoded secret strings."""

    id = "AUTH002"
    name = "JWT with hardcoded secret"
    severity = Severity.CRITICAL
    description = (
        "A JWT encode, decode, sign, or verify call uses a hardcoded string "
        "as the signing secret. Anyone with access to the source code can "
        "forge valid tokens, bypass authentication, and escalate privileges. "
        "Hardcoded secrets also cannot be rotated without redeploying."
    )
    fix = (
        "Load the JWT secret from an environment variable:\n"
        "  import os\n"
        '  JWT_SECRET = os.environ["JWT_SECRET_KEY"]\n'
        "  token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')\n"
        "Store the secret in .env and add .env to .gitignore.\n"
        "Use a strong random secret (at least 256 bits):\n"
        "  python -c \"import secrets; print(secrets.token_hex(32))\""
    )
    guide_url = "guides/02-authentication.md"
    owasp_id = "A02:2021"
    cwe_id = "CWE-321"
    confidence = "high"

    patterns: list[str] = [
        r'jwt\.(?:encode|decode|sign|verify)\s*\([^)]*["\'][a-zA-Z0-9_\-]{8,}["\']',
        r'(?:JWT_SECRET|jwt_secret|JWT_SECRET_KEY)\s*=\s*["\'][^"\']{3,}["\']',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        """Mask the hardcoded JWT secret value."""
        def _replacer(m: re.Match) -> str:
            val = m.group()
            return re.sub(r'(["\'])[a-zA-Z0-9_\-]{3,}\1', r'\1[REDACTED]\1', val)

        return re.sub(pattern, _replacer, line)


# ── AUTH003  InsecureCookieConfig ────────────────────────────────────


class InsecureCookieConfig(Rule):
    """Detect insecure cookie and session configuration."""

    id = "AUTH003"
    name = "Insecure cookie/session configuration"
    severity = Severity.HIGH
    description = (
        "Session cookies are configured without secure or httpOnly flags. "
        "Without 'secure', cookies are sent over unencrypted HTTP and can "
        "be intercepted by network attackers. Without 'httpOnly', cookies "
        "are accessible to JavaScript and vulnerable to XSS-based theft."
    )
    fix = (
        "Enable secure cookie settings in your framework:\n"
        "  Django:\n"
        "    SESSION_COOKIE_SECURE = True\n"
        "    SESSION_COOKIE_HTTPONLY = True\n"
        "  Flask:\n"
        "    app.config['SESSION_COOKIE_SECURE'] = True\n"
        "    app.config['SESSION_COOKIE_HTTPONLY'] = True\n"
        "  Express:\n"
        "    session({ cookie: { secure: true, httpOnly: true } })"
    )
    guide_url = "guides/02-authentication.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-614"
    confidence = "high"

    patterns: list[str] = [
        r'SESSION_COOKIE_SECURE\s*=\s*False',
        r'SESSION_COOKIE_HTTPONLY\s*=\s*False',
        r'httpOnly\s*:\s*false',
        r'cookie\(.*secure\s*:\s*false',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── AUTH004  DisabledCSRFProtection ──────────────────────────────────


class DisabledCSRFProtection(Rule):
    """Detect disabled CSRF protection in web frameworks."""

    id = "AUTH004"
    name = "Disabled CSRF protection"
    severity = Severity.HIGH
    description = (
        "Cross-Site Request Forgery (CSRF) protection is disabled. Without "
        "CSRF protection, attackers can trick authenticated users into "
        "submitting malicious requests by embedding hidden forms or "
        "JavaScript on third-party sites. This can lead to unauthorized "
        "state changes such as password resets or fund transfers."
    )
    fix = (
        "Enable CSRF protection using your framework's built-in middleware:\n"
        "  Django:\n"
        "    # Remove @csrf_exempt decorator\n"
        "    # Ensure 'django.middleware.csrf.CsrfViewMiddleware' is in MIDDLEWARE\n"
        "  Flask-WTF:\n"
        "    WTF_CSRF_ENABLED = True\n"
        "    csrf = CSRFProtect(app)\n"
        "  Express:\n"
        "    const csrf = require('csurf');\n"
        "    app.use(csrf({ cookie: true }));"
    )
    guide_url = "guides/02-authentication.md"
    owasp_id = "A01:2021"
    cwe_id = "CWE-352"
    confidence = "high"

    patterns: list[str] = [
        r'@csrf_exempt',
        r'WTF_CSRF_ENABLED\s*=\s*False',
        r'csrf\s*:\s*false',
        r'CSRF_ENABLED\s*=\s*False',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── AUTH005  HardcodedAuthCredentials ────────────────────────────────


class HardcodedAuthCredentials(Rule):
    """Detect hardcoded authentication credential tuples and Basic auth headers."""

    id = "AUTH005"
    name = "Hardcoded auth credentials"
    severity = Severity.CRITICAL
    description = (
        "Authentication credentials are hardcoded as a username/password "
        "tuple or a Base64-encoded Basic Authorization header. Anyone with "
        "access to the source code can extract these credentials and gain "
        "unauthorized access to the protected service."
    )
    fix = (
        "Load authentication credentials from environment variables:\n"
        "  import os\n"
        "  auth = (\n"
        '      os.environ["SERVICE_USERNAME"],\n'
        '      os.environ["SERVICE_PASSWORD"],\n'
        "  )\n"
        "  requests.get(url, auth=auth)\n"
        "Store credentials in .env and add .env to .gitignore.\n"
        "For Authorization headers, use a token from the environment:\n"
        '  headers = {"Authorization": f"Bearer {os.environ[\'API_TOKEN\']}"}'
    )
    guide_url = "guides/02-authentication.md"
    owasp_id = "A07:2021"
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r'auth\s*=\s*\(\s*["\'][^"\']+["\']\s*,\s*["\'][^"\']+["\']\s*\)',
        r'["\']Authorization["\']\s*:\s*["\']Basic\s+[A-Za-z0-9+/=]+["\']',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        """Mask hardcoded credential values."""
        def _replacer(m: re.Match) -> str:
            val = m.group()
            return re.sub(r'(["\'])[^"\']+\1', r'\1[REDACTED]\1', val)

        return re.sub(pattern, _replacer, line)


# ── AUTH006  DefaultWeakPermissions ──────────────────────────────────


class DefaultWeakPermissions(Rule):
    """Detect overly permissive default permission configurations."""

    id = "AUTH006"
    name = "Default/weak permission configuration"
    severity = Severity.MEDIUM
    description = (
        "Default permissions are configured to allow unauthenticated or "
        "unrestricted access. AllowAny, empty permission class lists, or "
        "anonymous access flags let any user — including unauthenticated "
        "attackers — access protected resources. This violates the "
        "principle of least privilege."
    )
    fix = (
        "Use restrictive default permissions that require authentication:\n"
        "  Django REST Framework:\n"
        "    REST_FRAMEWORK = {\n"
        "        'DEFAULT_PERMISSION_CLASSES': [\n"
        "            'rest_framework.permissions.IsAuthenticated',\n"
        "        ]\n"
        "    }\n"
        "  Per-view overrides (only where needed):\n"
        "    permission_classes = [IsAuthenticated, IsAdminUser]\n"
        "  Set allow_anonymous = False for views that handle sensitive data."
    )
    guide_url = "guides/03-authorization.md"
    owasp_id = "A01:2021"
    cwe_id = "CWE-862"
    confidence = "medium"

    patterns: list[str] = [
        r'DEFAULT_PERMISSION_CLASSES\s*=\s*\[.*AllowAny',
        r'IsAuthenticated.*False',
        r'permission_classes\s*=\s*\[\s*\]',
        r'allow_anonymous\s*=\s*True',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)
