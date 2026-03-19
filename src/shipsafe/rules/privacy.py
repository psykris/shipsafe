"""Privacy and PII detection rules for ShipSafe.

Detects personally identifiable information (PII) in log statements,
hardcoded SSN / credit card patterns, health data exposure, email
addresses in logs, and unencrypted PII storage patterns.

Every pattern is a class-level constant so you can audit the full catalogue
with a single grep:

    grep -A5 "patterns = \\[" src/shipsafe/rules/privacy.py

Design invariants
-----------------
- Patterns live on the class, never hidden inside methods.
- Matched values are always redacted before they appear in output.
- Every fix includes concrete, copy-pasteable remediation steps.
- owasp_id A02:2021 (Cryptographic Failures) covers unencrypted PII at rest.
"""

import re

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule


# ── PRI001  PIIInLogs ─────────────────────────────────────────────────


class PIIInLogs(Rule):
    """Detect PII field names written to log statements."""

    id = "PRI001"
    name = "PII written to logs"
    severity = Severity.HIGH
    description = (
        "A log or print statement contains variable names associated with "
        "personally identifiable information (PII) such as email, phone, "
        "password, SSN, or date of birth. Log aggregation systems (Datadog, "
        "Splunk, CloudWatch) retain this data indefinitely and are rarely "
        "subject to the same access controls as your database, creating a "
        "GDPR / CCPA compliance risk and a breach surface."
    )
    fix = (
        "Remove PII from log statements. Use structured logging with masked fields:\n"
        "  # Instead of:\n"
        "  logger.info(f'User login: email={email}')\n"
        "  # Use:\n"
        "  logger.info('User login', extra={'user_id': user.id})  # no PII\n"
        "  # Or mask with a helper:\n"
        "  def mask_email(e): return e[:2] + '***' + e[e.index('@'):]\n"
        "  logger.info('User login: %s', mask_email(email))\n"
        "Configure a log filter to strip PII fields automatically."
    )
    guide_url = "guides/10-privacy.md"
    owasp_id = "A02:2021"
    cwe_id = "CWE-532"
    confidence = "medium"

    file_extensions: list[str] = [".py", ".js", ".ts", ".jsx", ".tsx"]

    patterns: list[str] = [
        # Python logging / print with PII variable names
        r'(?:logger\.\w+|logging\.\w+|print)\s*\(.*\b(?:email|phone|ssn|password|passwd|dob|date_of_birth|credit_card|card_number|social_security)\b',
        # JavaScript console with PII field names
        r'console\.(?:log|warn|error|info)\s*\(.*\b(?:email|phone|ssn|password|dob|creditCard|cardNumber|socialSecurity)\b',
        # Python f-string log with PII
        r'(?:logger\.\w+|logging\.\w+|print)\s*\(\s*f["\'].*\{.*(?:email|phone|ssn|password|dob|credit_card)\b',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        """Mask PII values in log lines."""
        # Redact any email-shaped values
        line = re.sub(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', '[EMAIL REDACTED]', line)
        # Redact digit sequences that look like phone / SSN
        line = re.sub(r'\b\d{3}[-.\s]?\d{2,4}[-.\s]?\d{4}\b', '[NUMBER REDACTED]', line)
        return line


# ── PRI002  HardcodedSSN ──────────────────────────────────────────────


class HardcodedSSN(Rule):
    """Detect Social Security Number patterns hardcoded in source files."""

    id = "PRI002"
    name = "Hardcoded SSN pattern"
    severity = Severity.CRITICAL
    description = (
        "A string matching the US Social Security Number format (NNN-NN-NNNN) "
        "is hardcoded in source code. SSNs are highly sensitive PII — their "
        "exposure violates GDPR, CCPA, and numerous US state data-protection "
        "laws. Hardcoded SSNs also end up in git history permanently."
    )
    fix = (
        "Never store real SSNs in source code:\n"
        "  # In tests, use obviously fake patterns:\n"
        "  TEST_SSN = '000-00-0000'  # invalid SSN — safe for tests\n"
        "  # In production, store SSNs encrypted at rest:\n"
        "  encrypted_ssn = fernet.encrypt(ssn.encode())\n"
        "  db.save(user_id=uid, encrypted_ssn=encrypted_ssn)\n"
        "Tokenize or hash SSNs; never log or include them in error messages."
    )
    guide_url = "guides/10-privacy.md"
    owasp_id = "A02:2021"

    file_extensions: list[str] = [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb"]

    patterns: list[str] = [
        # SSN in string literal: "123-45-6789"  (exclude 000-00-0000 test value)
        r'["\'][0-9]{3}-[0-9]{2}-[0-9]{4}["\']',
        # SSN in assignment: ssn = "123-45-6789"
        r'\bssn\s*=\s*["\'][0-9]{3}-[0-9]{2}-[0-9]{4}["\']',
        # SSN as raw variable without obvious test prefix
        r'(?:social_security|ssn_number)\s*=\s*["\'][0-9]{3}-[0-9]{2}-[0-9]{4}["\']',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            # Skip well-known test placeholder (000-00-0000 is an invalid SSN)
            if "000-00-0000" in line:
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

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(r'[0-9]{3}-[0-9]{2}-[0-9]{4}', '[SSN REDACTED]', line)


# ── PRI003  HealthDataInLogs ──────────────────────────────────────────


class HealthDataInLogs(Rule):
    """Detect Protected Health Information (PHI) field names in log statements."""

    id = "PRI003"
    name = "Health data (PHI) in logs"
    severity = Severity.HIGH
    description = (
        "A log or print statement references Protected Health Information (PHI) "
        "field names such as diagnosis, medication, condition, or treatment. "
        "Logging PHI violates HIPAA in the US and health-data laws globally. "
        "Medical logs are an attractive target for attackers and are subject to "
        "mandatory breach notification requirements."
    )
    fix = (
        "Never log PHI. Use de-identified or aggregated identifiers:\n"
        "  # Instead of:\n"
        "  logger.info(f'Patient {patient_id} diagnosis: {diagnosis}')\n"
        "  # Use:\n"
        "  logger.info('Record updated', extra={'record_id': record_id})\n"
        "Implement a structured log filter that strips all PHI field names.\n"
        "Consult your HIPAA compliance officer before modifying health-data flows."
    )
    guide_url = "guides/10-privacy.md"
    owasp_id = "A02:2021"

    file_extensions: list[str] = [".py", ".js", ".ts", ".jsx", ".tsx"]

    patterns: list[str] = [
        # Python logging / print with PHI field names
        r'(?:logger\.\w+|logging\.\w+|print)\s*\(.*\b(?:diagnosis|medication|prescription|condition|treatment|patient_data|medical_record|health_record|icd_code|procedure_code)\b',
        # JavaScript console with PHI field names
        r'console\.(?:log|warn|error|info)\s*\(.*\b(?:diagnosis|medication|prescription|condition|treatment|patientData|medicalRecord|healthRecord)\b',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── PRI004  HardcodedEmail ────────────────────────────────────────────


class HardcodedEmail(Rule):
    """Detect real-looking email addresses hardcoded in source files."""

    id = "PRI004"
    name = "Hardcoded email address"
    severity = Severity.LOW
    description = (
        "A real-looking email address is hardcoded in source code. Beyond being "
        "a PII concern, hardcoded emails end up in git history, may be scraped "
        "by spam bots from public repositories, and create coupling that requires "
        "a code change to update. Use environment variables or configuration "
        "files for contact addresses."
    )
    fix = (
        "Move email addresses to environment variables or config:\n"
        "  import os\n"
        "  ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')\n"
        "  SUPPORT_EMAIL = os.environ['SUPPORT_EMAIL']\n"
        "For test fixtures, use addresses in the RFC 2606 reserved domains:\n"
        "  test@example.com, user@test.invalid, noreply@example.org"
    )
    guide_url = "guides/10-privacy.md"
    owasp_id = "A02:2021"

    file_extensions: list[str] = [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb"]

    patterns: list[str] = [
        # Email address hardcoded in a string literal (exclude safe example.com/test domains)
        r'["\'][A-Za-z0-9._%+\-]{2,}@(?!example\.|test\.|localhost)[A-Za-z0-9.\-]{3,}\.[A-Za-z]{2,}["\']',
        # Email in assignment: email = "user@company.com"
        r'\bemail\s*=\s*["\'][A-Za-z0-9._%+\-]{2,}@(?!example\.|test\.|localhost)[A-Za-z0-9.\-]{3,}\.[A-Za-z]{2,}["\']',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(
            r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}',
            '[EMAIL REDACTED]',
            line,
        )


# ── PRI005  UnencryptedPIIStorage ─────────────────────────────────────


class UnencryptedPIIStorage(Rule):
    """Detect PII written to plaintext files without encryption."""

    id = "PRI005"
    name = "Unencrypted PII storage"
    severity = Severity.HIGH
    description = (
        "Sensitive personal data (SSN, credit card, passport, health record) "
        "is written to a plaintext file (CSV, JSON, TXT) without any encryption "
        "wrapper. Plaintext PII at rest violates GDPR Article 32, PCI-DSS "
        "Requirement 3, and HIPAA Technical Safeguards, and makes a data breach "
        "trivially exploitable."
    )
    fix = (
        "Encrypt PII before writing to disk:\n"
        "  from cryptography.fernet import Fernet\n"
        "  key = Fernet.generate_key()  # store key in a secrets vault\n"
        "  fernet = Fernet(key)\n"
        "  with open('data.enc', 'wb') as f:\n"
        "      f.write(fernet.encrypt(json.dumps(record).encode()))\n"
        "Better: store PII in an encrypted database column (e.g. pgcrypto)\n"
        "or use a dedicated secrets/PII vault (AWS Macie, Vault, etc.)."
    )
    guide_url = "guides/10-privacy.md"
    owasp_id = "A02:2021"

    file_extensions: list[str] = [".py", ".js", ".ts"]

    patterns: list[str] = [
        # csv.writer / writer.writerow with PII field names
        r'(?:csv\.writer|writer\.writerow|json\.dump|f\.write|file\.write|fs\.write)\s*\(.*\b(?:ssn|social_security|credit_card|card_number|passport|health_record|medical_record|diagnosis)\b',
        # json.dump with PII keys
        r'json\.dump\s*\(.*["\'](?:ssn|credit_card|card_number|passport|medical_record)["\']',
        # Direct file write with PII variables
        r'(?:f|fh|file)\.write\s*\(.*\b(?:ssn|credit_card|passport_number|social_security)\b',
        # pandas to_csv/to_json export with PII variable names
        r'\b(?:ssn_data|pii_data|credit_card_data|patient_records)\b.*\.to_(?:csv|json|excel)\s*\(',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)
