"""Cryptographic and dangerous function rules for ShipSafe.

Detects disabled TLS verification, weak hashing algorithms, insecure
random number generation, and dangerous code execution functions.
"""

import re

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule


class TLSVerifyDisabledPython(Rule):
    """CRY001: TLS certificate verification disabled in Python."""

    id = "CRY001"
    name = "TLS verification disabled (Python)"
    severity = Severity.CRITICAL
    description = (
        "TLS certificate verification is disabled with verify=False. "
        "This allows man-in-the-middle attacks on HTTPS connections."
    )
    fix = (
        "Remove verify=False from requests calls:\n"
        "  requests.get(url)  # verify=True is the default\n"
        "If you need a custom CA bundle:\n"
        "  requests.get(url, verify='/path/to/ca-bundle.crt')"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A02:2021"
    cwe_id = "CWE-295"
    confidence = "high"
    file_extensions = [".py"]
    patterns = [r"verify\s*=\s*False"]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class TLSVerifyDisabledNode(Rule):
    """CRY002: TLS certificate verification disabled in Node.js."""

    id = "CRY002"
    name = "TLS verification disabled (Node.js)"
    severity = Severity.CRITICAL
    description = (
        "TLS certificate verification is disabled. "
        "This allows man-in-the-middle attacks on HTTPS connections."
    )
    fix = (
        "Remove rejectUnauthorized: false from TLS/HTTPS options.\n"
        "Remove NODE_TLS_REJECT_UNAUTHORIZED=0 from environment variables.\n"
        "If you need a custom CA, use the ca option instead."
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A02:2021"
    cwe_id = "CWE-295"
    confidence = "high"
    file_extensions = [".js", ".ts", ".jsx", ".tsx"]
    patterns = [
        r"rejectUnauthorized\s*:\s*false",
        r"NODE_TLS_REJECT_UNAUTHORIZED.*0",
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class MD5ForPasswords(Rule):
    """CRY003: MD5 hashing detected."""

    id = "CRY003"
    name = "MD5 hashing used"
    severity = Severity.HIGH
    description = (
        "MD5 hashing detected. MD5 is cryptographically broken and should "
        "not be used for passwords, integrity checks, or any security purpose."
    )
    fix = (
        "Use a strong hashing algorithm instead:\n"
        "  For passwords: bcrypt, argon2, or scrypt\n"
        "  For integrity: hashlib.sha256() or hashlib.sha3_256()"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A02:2021"
    cwe_id = "CWE-328"
    confidence = "high"
    file_extensions = [".py"]
    patterns = [r"hashlib\.md5\("]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class SHA1ForPasswords(Rule):
    """CRY004: SHA1 hashing detected."""

    id = "CRY004"
    name = "SHA1 hashing used"
    severity = Severity.HIGH
    description = (
        "SHA1 hashing detected. SHA1 is cryptographically weak and should "
        "not be used for passwords or security-sensitive operations."
    )
    fix = (
        "Use a strong hashing algorithm instead:\n"
        "  For passwords: bcrypt, argon2, or scrypt\n"
        "  For integrity: hashlib.sha256() or hashlib.sha3_256()"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A02:2021"
    cwe_id = "CWE-328"
    confidence = "high"
    file_extensions = [".py"]
    patterns = [r"hashlib\.sha1\("]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class MathRandomForSecurity(Rule):
    """CRY005: Math.random() used (insecure PRNG)."""

    id = "CRY005"
    name = "Math.random() used"
    severity = Severity.HIGH
    description = (
        "Math.random() is not cryptographically secure. It must not be "
        "used for tokens, passwords, session IDs, or any security purpose."
    )
    fix = (
        "Use the Web Crypto API instead:\n"
        "  crypto.randomUUID()\n"
        "  crypto.getRandomValues(new Uint8Array(32))\n"
        "In Node.js:\n"
        "  const { randomBytes } = require('crypto');"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A02:2021"
    cwe_id = "CWE-330"
    confidence = "medium"
    file_extensions = [".js", ".ts", ".jsx", ".tsx"]
    patterns = [r"Math\.random\(\)"]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class InsecureRandomPython(Rule):
    """CRY006: Python random module used (not cryptographically secure)."""

    id = "CRY006"
    name = "Insecure random (Python)"
    severity = Severity.MEDIUM
    description = (
        "The random module is not cryptographically secure. Functions like "
        "random.choice(), random.randint() etc. must not be used for "
        "tokens, passwords, or any security purpose."
    )
    fix = (
        "Use the secrets module for security-sensitive randomness:\n"
        "  import secrets\n"
        "  token = secrets.token_hex(32)\n"
        "  choice = secrets.choice(alphabet)"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A02:2021"
    cwe_id = "CWE-330"
    confidence = "medium"
    file_extensions = [".py"]
    patterns = [r"random\.(choice|choices|randint|random|sample|shuffle)\("]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        # Skip lines that use secrets or SystemRandom (those are safe)
        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            if "secrets." in line or "SystemRandom" in line:
                continue
            for pattern in self.patterns:
                if re.search(pattern, line):
                    findings.append(
                        self._make_finding(
                            file_path=file_path,
                            line_number=i,
                            snippet=self._redact(line, pattern),
                        )
                    )
                    break
        return findings


class EvalUsage(Rule):
    """CRY007: eval() usage detected."""

    id = "CRY007"
    name = "eval() usage"
    severity = Severity.CRITICAL
    description = (
        "eval() executes arbitrary code and is a critical injection risk. "
        "Attackers can execute arbitrary commands through user input "
        "passed to eval()."
    )
    fix = (
        "Replace eval() with safe alternatives:\n"
        "  Python: ast.literal_eval() for data, json.loads() for JSON\n"
        "  JavaScript: JSON.parse() for data, avoid eval entirely"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A03:2021"
    cwe_id = "CWE-95"
    confidence = "medium"
    patterns = [r"\beval\s*\("]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class ExecUsage(Rule):
    """CRY008: exec() usage detected."""

    id = "CRY008"
    name = "exec() usage"
    severity = Severity.HIGH
    description = (
        "exec() executes arbitrary Python code and is an injection risk. "
        "User input passed to exec() allows remote code execution."
    )
    fix = (
        "Remove exec() calls. Use safe alternatives:\n"
        "  For config: use a configuration file format (TOML, YAML)\n"
        "  For dynamic dispatch: use a dictionary of functions\n"
        "  For templates: use a sandboxed template engine"
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A03:2021"
    cwe_id = "CWE-95"
    confidence = "medium"
    file_extensions = [".py"]
    patterns = [r"\bexec\s*\("]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


class PickleLoads(Rule):
    """CRY009: pickle deserialization detected."""

    id = "CRY009"
    name = "Pickle deserialization"
    severity = Severity.HIGH
    description = (
        "pickle.load()/loads() deserializes arbitrary Python objects. "
        "Untrusted pickle data can execute arbitrary code during deserialization."
    )
    fix = (
        "Use safe serialization formats instead:\n"
        "  json.loads() for structured data\n"
        "  If pickle is required, only load from trusted sources and\n"
        "  consider using hmac to verify data integrity before loading."
    )
    guide_url = "guides/00-before-you-deploy.md"
    owasp_id = "A03:2021"
    cwe_id = "CWE-502"
    confidence = "medium"
    file_extensions = [".py"]
    patterns = [r"pickle\.(loads|load)\("]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)
