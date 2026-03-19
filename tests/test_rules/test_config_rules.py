"""Tests for the 5 configuration security rules (src/shipsafe/rules/config_rules.py).

Each rule is tested for:
    - True positive: scanning vulnerable fixture content produces >= 1 finding.
    - True negative: scanning clean fixture content produces 0 findings.
"""

from pathlib import Path

import pytest

from shipsafe.rules.config_rules import (
    DebugModeEnabled,
    NodeDevMode,
    CORSWildcard,
    VerboseErrors,
    AllowedHostsWildcard,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
VULNERABLE_CONFIG = FIXTURES / "vulnerable" / "config"
CLEAN_CONFIG = FIXTURES / "clean" / "config"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── Pre-load fixture content ──────────────────────────────────────────

VULN_DEBUG_DJANGO = _read(VULNERABLE_CONFIG / "debug_mode_django.py")
VULN_CORS_WILDCARD = _read(VULNERABLE_CONFIG / "cors_wildcard.js")
VULN_DEV_MODE = _read(VULNERABLE_CONFIG / "debug_mode_node.js")
VULN_VERBOSE_ERRORS = _read(VULNERABLE_CONFIG / "verbose_errors.py")

CLEAN_PRODUCTION = _read(CLEAN_CONFIG / "production_settings.py")
CLEAN_CORS = _read(CLEAN_CONFIG / "cors_restricted.js")


# ── CFG001: DebugModeEnabled ──────────────────────────────────────────


class TestDebugModeEnabled:
    rule = DebugModeEnabled()

    def test_true_positive(self):
        """DEBUG = True in Django settings should be detected."""
        findings = self.rule.scan("debug_mode_django.py", VULN_DEBUG_DJANGO)
        assert len(findings) >= 1

    def test_true_negative(self):
        """DEBUG = False in production settings should not trigger."""
        findings = self.rule.scan("production_settings.py", CLEAN_PRODUCTION)
        assert len(findings) == 0


# ── CFG002: NodeDevMode ───────────────────────────────────────────────


class TestNodeDevMode:
    rule = NodeDevMode()

    def test_true_positive(self):
        """NODE_ENV = 'development' should be detected."""
        findings = self.rule.scan("debug_mode_node.js", VULN_DEV_MODE)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Restricted CORS JS file should not trigger dev mode rule."""
        findings = self.rule.scan("cors_restricted.js", CLEAN_CORS)
        assert len(findings) == 0


# ── CFG003: CORSWildcard ─────────────────────────────────────────────


class TestCORSWildcard:
    rule = CORSWildcard()

    def test_true_positive(self):
        """CORS origin: '*' should be detected."""
        findings = self.rule.scan("cors_wildcard.js", VULN_CORS_WILDCARD)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Restricted CORS origin should not trigger."""
        findings = self.rule.scan("cors_restricted.js", CLEAN_CORS)
        assert len(findings) == 0


# ── CFG004: VerboseErrors ────────────────────────────────────────────


class TestVerboseErrors:
    rule = VerboseErrors()

    def test_true_positive(self):
        """PROPAGATE_EXCEPTIONS = True should be detected."""
        findings = self.rule.scan("verbose_errors.py", VULN_VERBOSE_ERRORS)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Production settings without verbose errors should not trigger."""
        findings = self.rule.scan("production_settings.py", CLEAN_PRODUCTION)
        assert len(findings) == 0


# ── CFG005: AllowedHostsWildcard ─────────────────────────────────────


class TestAllowedHostsWildcard:
    rule = AllowedHostsWildcard()

    def test_true_positive(self):
        """ALLOWED_HOSTS = ['*'] should be detected."""
        findings = self.rule.scan("debug_mode_django.py", VULN_DEBUG_DJANGO)
        assert len(findings) >= 1

    def test_true_negative(self):
        """ALLOWED_HOSTS with specific domain should not trigger."""
        findings = self.rule.scan("production_settings.py", CLEAN_PRODUCTION)
        assert len(findings) == 0
