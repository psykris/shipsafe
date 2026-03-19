"""Data exposure rules for ShipSafe.

Detects patterns that leak sensitive data through logs, error responses,
stack traces, and console output.
"""

import re

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule


class CredentialsInLogs(Rule):
    """DAT001: Sensitive data logged or printed."""

    id = "DAT001"
    name = "Credentials in logs"
    severity = Severity.HIGH
    description = (
        "Sensitive variable (password, secret, token, API key) found in a "
        "log or print statement. Secrets in logs can be exposed through log "
        "aggregation, monitoring dashboards, and log files."
    )
    fix = (
        "Never log sensitive values. Redact or mask credentials:\n"
        "  logger.info('User authenticated', extra={'user': username})\n"
        "  # Never: logger.info(f'Login with password={password}')"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A04:2021"
    cwe_id = "CWE-532"
    confidence = "medium"
    patterns = [
        (
            r"(log|logging|logger|print|console\.log)\s*\(.*"
            r"\b(password|passwd|secret|token|api_key|apikey|"
            r"auth_token|private_key|access_key|secret_key)\b"
        ),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        # Use case-insensitive matching for credential names
        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            for pattern in self.patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        self._make_finding(
                            file_path=file_path,
                            line_number=i,
                            snippet=self._redact(line, pattern),
                        )
                    )
                    break  # One finding per line max
        return findings


class StackTraceInResponse(Rule):
    """DAT002: Stack trace exposure in responses."""

    id = "DAT002"
    name = "Stack trace in response"
    severity = Severity.MEDIUM
    description = (
        "traceback formatting functions detected. Stack traces in responses "
        "reveal internal code structure, file paths, and library versions "
        "to attackers."
    )
    fix = (
        "Log stack traces server-side only. Return generic error messages:\n"
        "  except Exception:\n"
        "      logger.exception('Internal error')\n"
        "      return jsonify({'error': 'Internal server error'}), 500"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A04:2021"
    cwe_id = "CWE-209"
    confidence = "medium"
    file_extensions = [".py"]
    patterns = [r"traceback\.(format_exc|print_exc|format_exception)\("]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class VerboseErrorResponse(Rule):
    """DAT003: Verbose error details in HTTP response."""

    id = "DAT003"
    name = "Verbose error in response"
    severity = Severity.MEDIUM
    description = (
        "Traceback or detailed error information included in an HTTP "
        "response. This exposes internal application details to end users."
    )
    fix = (
        "Return generic error messages to clients:\n"
        "  return jsonify({'error': 'Something went wrong'}), 500\n"
        "Log detailed errors server-side only."
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A04:2021"
    cwe_id = "CWE-209"
    confidence = "medium"
    patterns = [
        r"(jsonify|json\.dumps|return).*traceback",
        r'"traceback"\s*:',  # "traceback" as a dict key in a response body
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class ConsoleLogSecrets(Rule):
    """DAT004: Sensitive data in console.log (JavaScript)."""

    id = "DAT004"
    name = "Secrets in console.log"
    severity = Severity.HIGH
    description = (
        "console.log() contains references to sensitive variables "
        "(password, token, secret, API key). Browser console output "
        "is visible to anyone with DevTools access."
    )
    fix = (
        "Remove console.log statements that contain secrets:\n"
        "  // Never: console.log('token:', authToken)\n"
        "Use a structured logger that redacts sensitive fields in production."
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A04:2021"
    cwe_id = "CWE-532"
    confidence = "medium"
    file_extensions = [".js", ".ts", ".jsx", ".tsx"]
    patterns = [
        r"console\.log\(.*\b(password|token|secret|api_key|apikey|key|credential)\b",
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)
