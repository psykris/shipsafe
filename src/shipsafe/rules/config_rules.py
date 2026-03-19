"""Configuration security rules for ShipSafe.

Detects insecure configuration patterns such as debug mode left enabled,
wildcard CORS, and overly permissive allowed hosts.
"""

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule


class DebugModeEnabled(Rule):
    """CFG001: Debug mode is enabled in Python code."""

    id = "CFG001"
    name = "Debug mode enabled"
    severity = Severity.HIGH
    description = (
        "DEBUG = True detected. Debug mode exposes detailed error pages, "
        "stack traces, and internal state to end users."
    )
    fix = (
        "Set DEBUG = False in production configuration. "
        "Use environment variables to control debug mode:\n"
        "  DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-489"
    confidence = "high"
    file_extensions = [".py"]
    patterns = [r"DEBUG\s*=\s*True"]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class NodeDevMode(Rule):
    """CFG002: NODE_ENV set to development."""

    id = "CFG002"
    name = "Node development mode"
    severity = Severity.MEDIUM
    description = (
        "NODE_ENV is set to 'development'. Applications in development mode "
        "may expose verbose errors and disable security features."
    )
    fix = (
        "Set NODE_ENV=production for production deployments. "
        "Never hardcode NODE_ENV to 'development' in committed code."
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-489"
    confidence = "medium"
    file_extensions = [".js", ".ts", ".jsx", ".tsx"]
    patterns = [
        r"NODE_ENV.*development",
        r"""['"]development['"]""",
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class CORSWildcard(Rule):
    """CFG003: Wildcard CORS configuration."""

    id = "CFG003"
    name = "CORS wildcard origin"
    severity = Severity.HIGH
    description = (
        "CORS is configured to allow all origins. This permits any website "
        "to make authenticated requests to your API."
    )
    fix = (
        "Restrict CORS to specific trusted origins:\n"
        "  Access-Control-Allow-Origin: https://yourdomain.com\n"
        "  cors({ origin: 'https://yourdomain.com' })"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-942"
    confidence = "high"
    patterns = [
        r"Access-Control-Allow-Origin.*\*",
        r"""origin:\s*['"]?\*""",
        r"cors\(\s*\)",
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class VerboseErrors(Rule):
    """CFG004: Verbose error configuration enabled."""

    id = "CFG004"
    name = "Verbose error configuration"
    severity = Severity.MEDIUM
    description = (
        "Verbose error propagation is enabled. This can expose internal "
        "application details, stack traces, and sensitive data in error responses."
    )
    fix = (
        "Disable verbose error settings in production:\n"
        "  PROPAGATE_EXCEPTIONS = False\n"
        "  TRAP_HTTP_EXCEPTIONS = False\n"
        "  app.config['DEBUG'] = False"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-209"
    confidence = "medium"
    patterns = [
        r"PROPAGATE_EXCEPTIONS\s*=\s*True",
        r"TRAP_HTTP_EXCEPTIONS\s*=\s*True",
        r"app\.config\[.DEBUG.\]\s*=\s*True",
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class AllowedHostsWildcard(Rule):
    """CFG005: ALLOWED_HOSTS contains wildcard."""

    id = "CFG005"
    name = "ALLOWED_HOSTS wildcard"
    severity = Severity.HIGH
    description = (
        "ALLOWED_HOSTS contains a wildcard '*'. This disables host header "
        "validation and enables HTTP host header attacks."
    )
    fix = (
        "Set ALLOWED_HOSTS to specific domains:\n"
        "  ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-644"
    confidence = "high"
    file_extensions = [".py"]
    patterns = [r"ALLOWED_HOSTS\s*=\s*\[.*\*.*\]"]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)
