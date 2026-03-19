"""Tests for the 6 authentication rules (src/shipsafe/rules/auth.py).

Each rule is tested for:
    - True positive: scanning vulnerable fixture produces >= 1 finding.
    - True negative: scanning clean fixture produces 0 findings.
"""

from pathlib import Path

from shipsafe.rules.auth import (
    HardcodedPasswordComparison,
    JWTHardcodedSecret,
    InsecureCookieConfig,
    DisabledCSRFProtection,
    HardcodedAuthCredentials,
    DefaultWeakPermissions,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
VULN_AUTH = FIXTURES / "vulnerable" / "auth"
CLEAN_AUTH = FIXTURES / "clean" / "auth"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


CLEAN_PY = _read(CLEAN_AUTH / "safe_auth.py")


# ── AUTH001: HardcodedPasswordComparison ─────────────────────────────

class TestHardcodedPasswordComparison:
    rule = HardcodedPasswordComparison()
    vuln = _read(VULN_AUTH / "hardcoded_password.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_password.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_auth.py uses bcrypt.checkpw, not password == "literal"
        findings = self.rule.scan("safe_auth.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_password.py", self.vuln)
        for f in findings:
            assert "admin123" not in f.snippet


# ── AUTH002: JWTHardcodedSecret ──────────────────────────────────────

class TestJWTHardcodedSecret:
    rule = JWTHardcodedSecret()
    vuln = _read(VULN_AUTH / "jwt_hardcoded_secret.py")

    def test_true_positive(self):
        findings = self.rule.scan("jwt_hardcoded_secret.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_auth.py loads JWT_SECRET from os.environ
        findings = self.rule.scan("safe_auth.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("jwt_hardcoded_secret.py", self.vuln)
        for f in findings:
            assert "my-super-secret-key" not in f.snippet


# ── AUTH003: InsecureCookieConfig ────────────────────────────────────

class TestInsecureCookieConfig:
    rule = InsecureCookieConfig()
    vuln = _read(VULN_AUTH / "insecure_session.py")

    def test_true_positive(self):
        findings = self.rule.scan("insecure_session.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_auth.py sets SESSION_COOKIE_SECURE = True
        findings = self.rule.scan("safe_auth.py", CLEAN_PY)
        assert len(findings) == 0


# ── AUTH004: DisabledCSRFProtection ──────────────────────────────────

class TestDisabledCSRFProtection:
    rule = DisabledCSRFProtection()
    vuln = _read(VULN_AUTH / "csrf_disabled.py")

    def test_true_positive(self):
        findings = self.rule.scan("csrf_disabled.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_auth.py has WTF_CSRF_ENABLED = True
        findings = self.rule.scan("safe_auth.py", CLEAN_PY)
        assert len(findings) == 0


# ── AUTH005: HardcodedAuthCredentials ────────────────────────────────

class TestHardcodedAuthCredentials:
    rule = HardcodedAuthCredentials()
    vuln = _read(VULN_AUTH / "hardcoded_credentials.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_credentials.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_auth.py uses os.environ for auth tuple
        findings = self.rule.scan("safe_auth.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_credentials.py", self.vuln)
        for f in findings:
            assert "password123" not in f.snippet


# ── AUTH006: DefaultWeakPermissions ──────────────────────────────────

class TestDefaultWeakPermissions:
    rule = DefaultWeakPermissions()
    vuln = _read(VULN_AUTH / "weak_permissions.py")

    def test_true_positive(self):
        findings = self.rule.scan("weak_permissions.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_auth.py uses IsAuthenticated, not AllowAny
        findings = self.rule.scan("safe_auth.py", CLEAN_PY)
        assert len(findings) == 0
