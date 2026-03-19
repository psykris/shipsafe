"""Tests for the 9 crypto/dangerous-function rules (src/shipsafe/rules/crypto.py).

Each rule is tested for:
    - True positive: scanning vulnerable fixture content produces >= 1 finding.
    - True negative: scanning clean fixture content produces 0 findings.
"""

from pathlib import Path

import pytest

from shipsafe.rules.crypto import (
    TLSVerifyDisabledPython,
    TLSVerifyDisabledNode,
    MD5ForPasswords,
    SHA1ForPasswords,
    MathRandomForSecurity,
    InsecureRandomPython,
    EvalUsage,
    ExecUsage,
    PickleLoads,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
VULNERABLE_CRYPTO = FIXTURES / "vulnerable" / "crypto"
CLEAN_CRYPTO = FIXTURES / "clean" / "crypto"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── Pre-load fixture content ──────────────────────────────────────────

VULN_VERIFY_PY = _read(VULNERABLE_CRYPTO / "verify_false_python.py")
VULN_VERIFY_NODE = _read(VULNERABLE_CRYPTO / "verify_false_node.js")
VULN_MD5 = _read(VULNERABLE_CRYPTO / "md5_password.py")
VULN_SHA1 = _read(VULNERABLE_CRYPTO / "sha1_password.py")
VULN_MATH_RANDOM = _read(VULNERABLE_CRYPTO / "math_random_security.js")
VULN_INSECURE_RANDOM = _read(VULNERABLE_CRYPTO / "insecure_random.py")
VULN_EVAL = _read(VULNERABLE_CRYPTO / "eval_usage.py")
VULN_PICKLE = _read(VULNERABLE_CRYPTO / "pickle_usage.py")

CLEAN_TLS = _read(CLEAN_CRYPTO / "proper_tls.py")
CLEAN_HASHING = _read(CLEAN_CRYPTO / "proper_hashing.py")
CLEAN_RANDOM = _read(CLEAN_CRYPTO / "secure_random.py")


# ── CRY001: TLSVerifyDisabledPython ──────────────────────────────────


class TestTLSVerifyDisabledPython:
    rule = TLSVerifyDisabledPython()

    def test_true_positive(self):
        """verify=False in Python requests should be detected."""
        findings = self.rule.scan("verify_false_python.py", VULN_VERIFY_PY)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Proper TLS usage should not trigger."""
        findings = self.rule.scan("proper_tls.py", CLEAN_TLS)
        assert len(findings) == 0


# ── CRY002: TLSVerifyDisabledNode ───────────────────────────────────


class TestTLSVerifyDisabledNode:
    rule = TLSVerifyDisabledNode()

    def test_true_positive(self):
        """rejectUnauthorized: false in Node.js should be detected."""
        findings = self.rule.scan("verify_false_node.js", VULN_VERIFY_NODE)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Clean Python TLS code should not trigger the Node rule."""
        # Use clean hashing (Python) as a safe .py file that has no Node patterns
        findings = self.rule.scan("proper_hashing.py", CLEAN_HASHING)
        assert len(findings) == 0


# ── CRY003: MD5ForPasswords ──────────────────────────────────────────


class TestMD5ForPasswords:
    rule = MD5ForPasswords()

    def test_true_positive(self):
        """hashlib.md5() usage should be detected."""
        findings = self.rule.scan("md5_password.py", VULN_MD5)
        assert len(findings) >= 1

    def test_true_negative(self):
        """bcrypt usage should not trigger MD5 rule."""
        findings = self.rule.scan("proper_hashing.py", CLEAN_HASHING)
        assert len(findings) == 0


# ── CRY004: SHA1ForPasswords ─────────────────────────────────────────


class TestSHA1ForPasswords:
    rule = SHA1ForPasswords()

    def test_true_positive(self):
        """hashlib.sha1() usage should be detected."""
        findings = self.rule.scan("sha1_password.py", VULN_SHA1)
        assert len(findings) >= 1

    def test_true_negative(self):
        """bcrypt usage should not trigger SHA1 rule."""
        findings = self.rule.scan("proper_hashing.py", CLEAN_HASHING)
        assert len(findings) == 0


# ── CRY005: MathRandomForSecurity ────────────────────────────────────


class TestMathRandomForSecurity:
    rule = MathRandomForSecurity()

    def test_true_positive(self):
        """Math.random() usage should be detected."""
        findings = self.rule.scan("math_random_security.js", VULN_MATH_RANDOM)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Clean Python secrets module should not trigger Math.random rule."""
        findings = self.rule.scan("secure_random.py", CLEAN_RANDOM)
        assert len(findings) == 0


# ── CRY006: InsecureRandomPython ─────────────────────────────────────


class TestInsecureRandomPython:
    rule = InsecureRandomPython()

    def test_true_positive(self):
        """random.choices() and random.randint() should be detected."""
        findings = self.rule.scan("insecure_random.py", VULN_INSECURE_RANDOM)
        assert len(findings) >= 1

    def test_true_negative(self):
        """secrets module usage should not trigger insecure random rule."""
        findings = self.rule.scan("secure_random.py", CLEAN_RANDOM)
        assert len(findings) == 0


# ── CRY007: EvalUsage ────────────────────────────────────────────────


class TestEvalUsage:
    rule = EvalUsage()

    def test_true_positive(self):
        """eval() usage should be detected."""
        findings = self.rule.scan("eval_usage.py", VULN_EVAL)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Clean code without eval should not trigger."""
        findings = self.rule.scan("proper_hashing.py", CLEAN_HASHING)
        assert len(findings) == 0


# ── CRY008: ExecUsage ────────────────────────────────────────────────


class TestExecUsage:
    rule = ExecUsage()

    def test_true_positive(self):
        """exec() usage should be detected."""
        # The eval_usage.py fixture also contains exec()
        findings = self.rule.scan("eval_usage.py", VULN_EVAL)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Clean code without exec should not trigger."""
        findings = self.rule.scan("proper_hashing.py", CLEAN_HASHING)
        assert len(findings) == 0


# ── CRY009: PickleLoads ──────────────────────────────────────────────


class TestPickleLoads:
    rule = PickleLoads()

    def test_true_positive(self):
        """pickle.loads() and pickle.load() should be detected."""
        findings = self.rule.scan("pickle_usage.py", VULN_PICKLE)
        assert len(findings) >= 1

    def test_true_negative(self):
        """Clean code without pickle should not trigger."""
        findings = self.rule.scan("proper_hashing.py", CLEAN_HASHING)
        assert len(findings) == 0
