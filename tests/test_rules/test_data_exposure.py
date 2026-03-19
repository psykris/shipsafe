"""Tests for the 4 data exposure rules (src/shipsafe/rules/data_exposure.py).

Each rule is tested for:
    - True positive: scanning vulnerable fixture content produces >= 1 finding.
    - True negative: scanning clean fixture content produces 0 findings.
"""

from pathlib import Path

import pytest

from shipsafe.rules.data_exposure import (
    CredentialsInLogs,
    StackTraceInResponse,
    VerboseErrorResponse,
    ConsoleLogSecrets,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
VULNERABLE_DATA = FIXTURES / "vulnerable" / "data_exposure"
CLEAN_DATA = FIXTURES / "clean" / "data_exposure"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── Pre-load fixture content ──────────────────────────────────────────

VULN_CREDS_IN_LOGS = _read(VULNERABLE_DATA / "credentials_in_logs.py")
VULN_VERBOSE_ERRORS = _read(VULNERABLE_DATA / "verbose_errors.py")
VULN_CONSOLE_LOG = _read(VULNERABLE_DATA / "console_log_secrets.js")

CLEAN_LOGGING = _read(CLEAN_DATA / "safe_logging.py")
CLEAN_ERRORS = _read(CLEAN_DATA / "safe_errors.py")


# ── DAT001: CredentialsInLogs ────────────────────────────────────────


class TestCredentialsInLogs:
    rule = CredentialsInLogs()

    def test_true_positive(self):
        """Logging password/token values should be detected."""
        findings = self.rule.scan("credentials_in_logs.py", VULN_CREDS_IN_LOGS)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Safe logging without credentials should not trigger."""
        findings = self.rule.scan("safe_logging.py", CLEAN_LOGGING)
        assert len(findings) == 0


# ── DAT002: StackTraceInResponse ─────────────────────────────────────


class TestStackTraceInResponse:
    rule = StackTraceInResponse()

    def test_true_positive(self):
        """traceback.format_exc() usage should be detected."""
        findings = self.rule.scan("verbose_errors.py", VULN_VERBOSE_ERRORS)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Safe error handling without stack traces should not trigger."""
        findings = self.rule.scan("safe_errors.py", CLEAN_ERRORS)
        assert len(findings) == 0


# ── DAT003: VerboseErrorResponse ─────────────────────────────────────


class TestVerboseErrorResponse:
    rule = VerboseErrorResponse()

    def test_true_positive(self):
        """jsonify(...traceback...) should be detected."""
        findings = self.rule.scan("verbose_errors.py", VULN_VERBOSE_ERRORS)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Generic error response should not trigger."""
        findings = self.rule.scan("safe_errors.py", CLEAN_ERRORS)
        assert len(findings) == 0


# ── DAT004: ConsoleLogSecrets ────────────────────────────────────────


class TestConsoleLogSecrets:
    rule = ConsoleLogSecrets()

    def test_true_positive(self):
        """console.log with token/password references should be detected."""
        findings = self.rule.scan("console_log_secrets.js", VULN_CONSOLE_LOG)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Safe Python logging should not trigger console.log rule."""
        findings = self.rule.scan("safe_logging.py", CLEAN_LOGGING)
        assert len(findings) == 0
