"""Tests for the 18 secrets detection rules (src/shipsafe/rules/secrets.py).

Each rule is tested for:
    - True positive: scanning vulnerable fixture content produces >= 1 finding.
    - True negative: scanning clean fixture content produces 0 findings.
    - Redaction: the actual secret value must NOT appear in the finding snippet.
"""

from pathlib import Path

import pytest

from shipsafe.rules.secrets import (
    HardcodedOpenAIKey,
    HardcodedAnthropicKey,
    HardcodedAWSKey,
    HardcodedGCPKey,
    HardcodedStripeKey,
    HardcodedGitHubToken,
    HardcodedGitLabToken,
    HardcodedSlackToken,
    HardcodedDatabaseURL,
    PrivateKeyInSource,
    HardcodedTwilioKey,
    HardcodedSendGridKey,
    HardcodedMailgunKey,
    HardcodedNPMToken,
    HardcodedPyPIToken,
    HardcodedDockerHubToken,
    HardcodedVercelToken,
    HardcodedSupabaseJWT,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
VULNERABLE_SECRETS = FIXTURES / "vulnerable" / "secrets"
CLEAN_SECRETS = FIXTURES / "clean" / "secrets"


# ── Helpers ────────────────────────────────────────────────────────────


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# Clean fixture contents (shared across most secret rule true-negative tests)
CLEAN_PY = _read(CLEAN_SECRETS / "env_var_usage.py")
CLEAN_JS = _read(CLEAN_SECRETS / "env_var_usage.js")


# ── SEC001: HardcodedOpenAIKey ─────────────────────────────────────────


class TestHardcodedOpenAIKey:
    rule = HardcodedOpenAIKey()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_openai_key.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_openai_key.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_openai_key.py", self.vuln_content)
        for f in findings:
            assert "abc123def456ghi789jkl012mno345pqr678stu901vwx234" not in f.snippet


# ── SEC002: HardcodedAnthropicKey ──────────────────────────────────────


class TestHardcodedAnthropicKey:
    rule = HardcodedAnthropicKey()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_anthropic_key.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_anthropic_key.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_anthropic_key.py", self.vuln_content)
        for f in findings:
            assert "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR" not in f.snippet


# ── SEC003: HardcodedAWSKey ────────────────────────────────────────────


class TestHardcodedAWSKey:
    rule = HardcodedAWSKey()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_aws_key.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_aws_key.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_aws_key.py", self.vuln_content)
        for f in findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in f.snippet


# ── SEC004: HardcodedGCPKey ────────────────────────────────────────────


class TestHardcodedGCPKey:
    rule = HardcodedGCPKey()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_gcp_key.js")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_gcp_key.js", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.js", CLEAN_JS)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_gcp_key.js", self.vuln_content)
        for f in findings:
            assert "AIzaSyA1B2C3D4E5F6G7H8I9J0KlMnOpQrStUvW" not in f.snippet


# ── SEC005: HardcodedStripeKey ─────────────────────────────────────────


class TestHardcodedStripeKey:
    rule = HardcodedStripeKey()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_stripe_key.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_stripe_key.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_stripe_key.py", self.vuln_content)
        for f in findings:
            assert "sk_live_FakeStripeKeyForShipSafeTestSuite000" not in f.snippet


# ── SEC006: HardcodedGitHubToken ───────────────────────────────────────


class TestHardcodedGitHubToken:
    rule = HardcodedGitHubToken()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_github_token.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_github_token.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_github_token.py", self.vuln_content)
        for f in findings:
            assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234" not in f.snippet


# ── SEC007: HardcodedGitLabToken ───────────────────────────────────────


class TestHardcodedGitLabToken:
    rule = HardcodedGitLabToken()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_gitlab_token.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_gitlab_token.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_gitlab_token.py", self.vuln_content)
        for f in findings:
            assert "glpat-abcdefghijklmnopqrstuvwx" not in f.snippet


# ── SEC008: HardcodedSlackToken ────────────────────────────────────────


class TestHardcodedSlackToken:
    rule = HardcodedSlackToken()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_slack_token.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_slack_token.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_slack_token.py", self.vuln_content)
        for f in findings:
            assert "xoxb-0000000000000-0000000000000-FakeSlackTokenForShipSafeTests" not in f.snippet


# ── SEC009: HardcodedDatabaseURL ───────────────────────────────────────


class TestHardcodedDatabaseURL:
    rule = HardcodedDatabaseURL()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_db_url.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_db_url.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_db_url.py", self.vuln_content)
        for f in findings:
            # The actual password should not appear in the snippet
            assert "supersecret" not in f.snippet
            assert "password123" not in f.snippet


# ── SEC010: PrivateKeyInSource ─────────────────────────────────────────


class TestPrivateKeyInSource:
    rule = PrivateKeyInSource()
    vuln_content = _read(VULNERABLE_SECRETS / "private_key.py")

    def test_true_positive(self):
        findings = self.rule.scan("private_key.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("private_key.py", self.vuln_content)
        for f in findings:
            assert "-----BEGIN RSA PRIVATE KEY-----" not in f.snippet


# ── SEC011: HardcodedTwilioKey ─────────────────────────────────────────


class TestHardcodedTwilioKey:
    rule = HardcodedTwilioKey()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_twilio_key.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_twilio_key.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_twilio_key.py", self.vuln_content)
        for f in findings:
            assert "SKFakeTwilioKeyForShipSafeTests000" not in f.snippet


# ── SEC012: HardcodedSendGridKey ───────────────────────────────────────


class TestHardcodedSendGridKey:
    rule = HardcodedSendGridKey()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_sendgrid_key.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_sendgrid_key.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_sendgrid_key.py", self.vuln_content)
        for f in findings:
            assert "SG.FakeSendGridKey_000000.FakeShipSafeTestFixtureAAAAAAAAAAAAAAAAAAAA" not in f.snippet


# ── SEC013: HardcodedMailgunKey ────────────────────────────────────────


class TestHardcodedMailgunKey:
    rule = HardcodedMailgunKey()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_mailgun_key.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_mailgun_key.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_mailgun_key.py", self.vuln_content)
        for f in findings:
            assert "key-0123456789abcdef0123456789abcdef" not in f.snippet


# ── SEC014: HardcodedNPMToken ──────────────────────────────────────────


class TestHardcodedNPMToken:
    rule = HardcodedNPMToken()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_npm_token.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_npm_token.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_npm_token.py", self.vuln_content)
        for f in findings:
            assert "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" not in f.snippet


# ── SEC015: HardcodedPyPIToken ─────────────────────────────────────────


class TestHardcodedPyPIToken:
    rule = HardcodedPyPIToken()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_pypi_token.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_pypi_token.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_pypi_token.py", self.vuln_content)
        for f in findings:
            assert "pypi-AgEIcHlwaS5vcmcCJGFiY2RlZmdoaWprbG1ub3BxcnN0" not in f.snippet


# ── SEC016: HardcodedDockerHubToken ────────────────────────────────────


class TestHardcodedDockerHubToken:
    rule = HardcodedDockerHubToken()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_docker_token.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_docker_token.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_docker_token.py", self.vuln_content)
        for f in findings:
            assert "dckr_pat_abcdefghijklmnopqrstuvwx" not in f.snippet


# ── SEC017: HardcodedVercelToken ───────────────────────────────────────


class TestHardcodedVercelToken:
    rule = HardcodedVercelToken()
    vuln_content = _read(VULNERABLE_SECRETS / "hardcoded_vercel_token.py")

    def test_true_positive(self):
        findings = self.rule.scan("hardcoded_vercel_token.py", self.vuln_content)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("hardcoded_vercel_token.py", self.vuln_content)
        for f in findings:
            assert "vercel_abcdefghijklmnopqrstuvwx" not in f.snippet


# ── SEC018: HardcodedSupabaseJWT ───────────────────────────────────────


class TestHardcodedSupabaseJWT:
    """Test SEC018 with inline content since no dedicated fixture exists."""

    rule = HardcodedSupabaseJWT()

    VULN_CONTENT = (
        '# Supabase config\n'
        'supabase_url = "https://abc.supabase.co"\n'
        'anon_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9"\n'
    )

    def test_true_positive(self):
        findings = self.rule.scan("config.py", self.VULN_CONTENT)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("env_var_usage.py", CLEAN_PY)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("config.py", self.VULN_CONTENT)
        for f in findings:
            assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in f.snippet
