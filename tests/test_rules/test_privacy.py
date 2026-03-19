"""Tests for privacy and PII detection rules (PRI001–PRI005)."""
from pathlib import Path

import pytest

from shipsafe.rules.privacy import (
    HardcodedEmail,
    HardcodedSSN,
    HealthDataInLogs,
    PIIInLogs,
    UnencryptedPIIStorage,
)

VULN_DIR = Path(__file__).parent.parent / "fixtures" / "vulnerable" / "privacy"
CLEAN_DIR = Path(__file__).parent.parent / "fixtures" / "clean" / "privacy"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── PRI001 ────────────────────────────────────────────────────────────


class TestPIIInLogs:
    rule = PIIInLogs()
    vuln = _read(VULN_DIR / "pii_logging.py")
    clean = _read(CLEAN_DIR / "safe_privacy.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_email_in_logger(self):
        code = 'logger.info("User email: %s", email)'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_phone_in_logging(self):
        code = 'logging.warning("Phone: %s", phone)'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_password_in_print(self):
        code = 'print(f"Debug password={password}")'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_ssn_in_logger(self):
        code = 'logger.debug("User ssn: %s", ssn)'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_redaction(self):
        code = 'logger.info("User: john@example.com phone 555-123-4567")'
        findings = self.rule.scan("app.py", code)
        # Snippet should not contain raw email
        for f in findings:
            assert "john@example.com" not in f.snippet

    def test_rule_id(self):
        assert self.rule.id == "PRI001"


# ── PRI002 ────────────────────────────────────────────────────────────


class TestHardcodedSSN:
    rule = HardcodedSSN()
    vuln = _read(VULN_DIR / "hardcoded_ssn.py")
    clean = _read(CLEAN_DIR / "safe_privacy.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_ssn_in_string_literal(self):
        code = 'test_ssn = "123-45-6789"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_test_placeholder_excluded(self):
        # 000-00-0000 is an invalid SSN — safe placeholder
        code = 'TEST_SSN = "000-00-0000"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) == 0

    def test_redaction(self):
        code = 'ssn = "987-65-4321"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1
        for f in findings:
            assert "987-65-4321" not in f.snippet
            assert "[SSN REDACTED]" in f.snippet

    def test_rule_id(self):
        assert self.rule.id == "PRI002"


# ── PRI003 ────────────────────────────────────────────────────────────


class TestHealthDataInLogs:
    rule = HealthDataInLogs()
    vuln = _read(VULN_DIR / "health_data_logs.py")
    clean = _read(CLEAN_DIR / "safe_privacy.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_diagnosis_in_logger(self):
        code = 'logger.info("Patient diagnosis: %s", diagnosis)'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_medication_in_logging(self):
        code = 'logging.info("Medication: %s", medication)'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_treatment_in_logger(self):
        code = 'logger.debug("Treatment: %s", treatment)'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_non_phi_log_is_safe(self):
        code = 'logger.info("Record updated", extra={"record_id": record_id})'
        findings = self.rule.scan("app.py", code)
        assert len(findings) == 0

    def test_rule_id(self):
        assert self.rule.id == "PRI003"


# ── PRI004 ────────────────────────────────────────────────────────────


class TestHardcodedEmail:
    rule = HardcodedEmail()
    vuln = _read(VULN_DIR / "hardcoded_email.py")
    clean = _read(CLEAN_DIR / "safe_privacy.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_hardcoded_company_email(self):
        code = 'ADMIN_EMAIL = "admin@mycompany.com"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_example_domain_is_safe(self):
        # RFC 2606 reserved domains — safe test addresses
        code = 'TEST_EMAIL = "test@example.com"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) == 0

    def test_test_domain_is_safe(self):
        code = 'email = "user@test.invalid"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) == 0

    def test_redaction(self):
        code = 'ADMIN_EMAIL = "admin@mycompany.com"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1
        for f in findings:
            assert "admin@mycompany.com" not in f.snippet
            assert "[EMAIL REDACTED]" in f.snippet

    def test_rule_id(self):
        assert self.rule.id == "PRI004"


# ── PRI005 ────────────────────────────────────────────────────────────


class TestUnencryptedPIIStorage:
    rule = UnencryptedPIIStorage()
    vuln = _read(VULN_DIR / "unencrypted_pii.py")
    clean = _read(CLEAN_DIR / "safe_privacy.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_csv_writer_writerow_with_ssn(self):
        code = 'writer.writerow([user["name"], user["ssn"], user["email"]])'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_json_dump_with_credit_card(self):
        code = 'json.dump({"credit_card": card_num, "amount": 100}, f)'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_file_write_with_passport(self):
        code = 'fh.write(f"record passport_number={user[\'passport\']}")'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_rule_id(self):
        assert self.rule.id == "PRI005"
