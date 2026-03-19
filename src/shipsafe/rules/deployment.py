"""Deployment security rules for ShipSafe.

Detects insecure deployment configurations including Dockerfiles running
as root, exposed debug routes, build secrets baked into images, services
binding to all interfaces, exposed source maps, and misconfigured security
headers.

Every pattern is a class-level constant so the full catalogue is auditable:

    grep -A5 "patterns = \\[" src/shipsafe/rules/deployment.py

Design invariants
-----------------
- Patterns live on the class, never hidden inside methods.
- Dockerfile rules override scan() to gate on filename since Dockerfiles
  lack a standard file extension.
- Every fix includes actionable, copy-paste remediation steps.
"""

import re

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule

# ── Shared constants ────────────────────────────────────────────────

_GUIDE_URL = "guides/06-deployment-hardening.md"


def _is_dockerfile(file_path: str) -> bool:
    """Check if the given file path refers to a Dockerfile."""
    lower = file_path.lower()
    return lower.endswith(("dockerfile", ".dockerfile")) or "Dockerfile" in file_path


# ── DEP001  DockerfileRunningAsRoot ─────────────────────────────────


class DockerfileRunningAsRoot(Rule):
    """Detect Dockerfiles without a USER directive (running as root)."""

    id = "DEP001"
    name = "Dockerfile running as root"
    severity = Severity.HIGH
    description = (
        "This Dockerfile does not contain a USER directive. By default, "
        "Docker containers run as root, which violates the principle of "
        "least privilege and increases the blast radius of container escapes."
    )
    fix = (
        "Add a non-root user before your CMD or ENTRYPOINT:\n"
        "  RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser\n"
        "  USER appuser\n"
        "  CMD [\"python\", \"app.py\"]\n"
        "Or use a numeric UID:\n"
        "  USER 1001"
    )
    guide_url = _GUIDE_URL
    owasp_id = "A05:2021"
    cwe_id = "CWE-250"
    confidence = "high"

    patterns: list[str] = []

    def scan(self, file_path: str, content: str) -> list[Finding]:
        if not _is_dockerfile(file_path):
            return []
        # Check if there is a USER directive
        if not re.search(r"^USER\s+\S+", content, re.MULTILINE):
            return [
                self._make_finding(
                    file_path=file_path,
                    line_number=1,
                    snippet="# No USER directive found in Dockerfile",
                )
            ]
        return []


# ── DEP002  ExposedDebugAdminRoutes ─────────────────────────────────


class ExposedDebugAdminRoutes(Rule):
    """Detect route registrations for debug/admin endpoints."""

    id = "DEP002"
    name = "Exposed debug/admin routes"
    severity = Severity.HIGH
    description = (
        "A debug or admin route is registered without apparent authentication. "
        "Exposed admin panels, debug endpoints, and API explorers are common "
        "targets for attackers and can leak sensitive application internals."
    )
    fix = (
        "1. Protect admin routes with authentication middleware:\n"
        "   Express: app.use('/admin', authMiddleware, adminRouter)\n"
        "   Django:  path('admin/', admin.site.urls)  # uses built-in auth\n"
        "   Flask:   @app.before_request + login check\n"
        "2. Remove debug endpoints before deploying to production.\n"
        "3. If Swagger/GraphQL is needed, restrict access by IP or auth."
    )
    guide_url = _GUIDE_URL
    owasp_id = "A01:2021"
    cwe_id = "CWE-489"
    confidence = "medium"

    patterns: list[str] = [
        r'(?:route|app\.get|app\.post|router\.get|router\.post|path)\s*\(\s*["\']\/(?:admin|debug|phpmyadmin|swagger|graphql|actuator)["\']',
        r"urlpatterns.*(?:admin|debug)/",
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── DEP003  BuildSecretsInDockerfile ────────────────────────────────


class BuildSecretsInDockerfile(Rule):
    """Detect secrets passed via ENV/ARG in Dockerfiles."""

    id = "DEP003"
    name = "Build secrets in Dockerfile"
    severity = Severity.CRITICAL
    description = (
        "Secrets are passed via ENV or ARG instructions in a Dockerfile. "
        "These values are baked into the image layer history and can be "
        "extracted by anyone with access to the image using "
        "'docker history' or 'docker inspect'."
    )
    fix = (
        "1. Never use ENV or ARG for secrets in Dockerfiles.\n"
        "2. Use Docker BuildKit secrets for build-time secrets:\n"
        "   RUN --mount=type=secret,id=my_secret cat /run/secrets/my_secret\n"
        "   Build with: docker build --secret id=my_secret,src=./secret.txt .\n"
        "3. For runtime secrets, use Docker secrets or mount a .env file:\n"
        "   docker run --env-file .env myimage"
    )
    guide_url = _GUIDE_URL
    owasp_id = "A07:2021"
    cwe_id = "CWE-200"
    confidence = "high"

    patterns: list[str] = [
        r"^(?:ENV|ARG)\s+(?:.*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIALS))",
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        if not _is_dockerfile(file_path):
            return []
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        def _replacer(m: re.Match) -> str:
            val = m.group()
            # Keep the instruction keyword but redact the value
            parts = val.split(None, 1)
            if len(parts) >= 2:
                key = parts[1].split("=")[0]
                return f"{parts[0]} {key}=...REDACTED"
            return val

        return re.sub(pattern, _replacer, line, flags=re.IGNORECASE)


# ── DEP004  BindingToAllInterfaces ──────────────────────────────────


class BindingToAllInterfaces(Rule):
    """Detect services binding to 0.0.0.0 (all network interfaces)."""

    id = "DEP004"
    name = "Binding to all interfaces (0.0.0.0)"
    severity = Severity.MEDIUM
    description = (
        "The service is binding to 0.0.0.0, which listens on all network "
        "interfaces. In production, this may expose the service to "
        "unintended networks unless a firewall or reverse proxy is in place."
    )
    fix = (
        "1. Bind to 127.0.0.1 for local-only access:\n"
        "   Python:     app.run(host='127.0.0.1', port=8000)\n"
        "   Node.js:    server.listen(8000, '127.0.0.1')\n"
        "2. In production, use a reverse proxy (nginx, Caddy) to handle\n"
        "   external traffic and bind the app to localhost.\n"
        "3. If 0.0.0.0 is intentional (e.g. inside a container), add a\n"
        "   firewall rule or security group to restrict access."
    )
    guide_url = _GUIDE_URL
    owasp_id = "A05:2021"
    cwe_id = "CWE-200"
    confidence = "medium"

    patterns: list[str] = [
        r'(?:host|bind|listen)\s*(?:=|:)\s*["\']0\.0\.0\.0["\']',
        r'\.listen\s*\(\s*(?:\d+\s*,\s*)?["\']0\.0\.0\.0["\']',
        r'app\.run\s*\(.*host\s*=\s*["\']0\.0\.0\.0["\']',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── DEP005  ExposedSourceMaps ───────────────────────────────────────


class ExposedSourceMaps(Rule):
    """Detect source maps enabled in production configuration."""

    id = "DEP005"
    name = "Exposed source maps"
    severity = Severity.MEDIUM
    description = (
        "Source maps are enabled or present in what appears to be production "
        "configuration. Source maps expose your original source code, making "
        "it trivial for attackers to find vulnerabilities, understand business "
        "logic, and discover hardcoded values."
    )
    fix = (
        "1. Disable source maps in production builds:\n"
        "   Webpack:    devtool: false  (in production config)\n"
        "   Vue CLI:    productionSourceMap: false\n"
        "   React CRA:  GENERATE_SOURCEMAP=false in .env.production\n"
        "2. Remove sourceMappingURL comments from production bundles.\n"
        "3. If source maps are needed for error tracking, upload them\n"
        "   to your error monitoring service (Sentry, Datadog) and\n"
        "   do not serve them publicly."
    )
    guide_url = _GUIDE_URL
    owasp_id = "A05:2021"
    cwe_id = "CWE-540"
    confidence = "medium"

    file_extensions: list[str] = [".js", ".ts", ".json", ".vue"]

    patterns: list[str] = [
        r"sourceMappingURL\s*=",
        r'devtool\s*:\s*["\'](?:source-map|eval-source-map|cheap-module-source-map)["\']',
        r"productionSourceMap\s*:\s*true",
        r"GENERATE_SOURCEMAP\s*=\s*true",
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── DEP006  InsecureSecurityHeaders ─────────────────────────────────


class InsecureSecurityHeaders(Rule):
    """Detect insecure security header configurations."""

    id = "DEP006"
    name = "Insecure security headers configuration"
    severity = Severity.MEDIUM
    description = (
        "Security headers are configured with insecure values. Weak or "
        "disabled security headers leave the application vulnerable to "
        "clickjacking, MIME-type sniffing, XSS, and man-in-the-middle attacks."
    )
    fix = (
        "Set proper security headers in your server or reverse proxy:\n"
        "  X-Frame-Options: DENY\n"
        "  X-Content-Type-Options: nosniff\n"
        "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
        "  Content-Security-Policy: default-src 'self'\n"
        "Or use a library like helmet (Node.js) or django-secure (Python)."
    )
    guide_url = _GUIDE_URL
    owasp_id = "A05:2021"
    cwe_id = "CWE-693"
    confidence = "medium"

    patterns: list[str] = [
        r"X-Frame-Options\s*:\s*[\"']?ALLOWALL",
        r"X-Content-Type-Options\s*:\s*[\"']?none",
        r"Strict-Transport-Security.*max-age\s*=\s*0",
        r"Content-Security-Policy.*unsafe-inline.*unsafe-eval",
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)
