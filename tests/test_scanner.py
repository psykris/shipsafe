"""Integration tests for the ShipSafe scanner orchestrator."""

from pathlib import Path

from shipsafe.finding import Severity
from shipsafe.scanner import Scanner

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = str(FIXTURES / "vulnerable")
CLEAN = str(FIXTURES / "clean")


class TestScannerIntegration:
    """Integration tests that run the full scanner against fixture directories."""

    def test_scan_vulnerable_fixtures_finds_issues(self):
        """Scanning vulnerable fixtures should produce findings."""
        scanner = Scanner()
        result = scanner.scan(VULNERABLE)
        assert result.findings, "Expected findings in vulnerable fixtures"
        assert result.files_scanned > 0

    def test_scan_clean_fixtures_no_secret_findings(self):
        """Scanning clean fixtures should produce no secret findings."""
        scanner = Scanner()
        result = scanner.scan(CLEAN)
        secret_findings = [f for f in result.findings if f.rule_id.startswith("SEC")]
        assert not secret_findings, (
            f"Found {len(secret_findings)} secret findings in clean fixtures: "
            + ", ".join(f"{f.rule_id} in {f.file_path}" for f in secret_findings)
        )

    def test_scan_returns_scan_result(self):
        """Scanner returns a ScanResult with all expected fields."""
        scanner = Scanner()
        result = scanner.scan(VULNERABLE)
        assert hasattr(result, "findings")
        assert hasattr(result, "score")
        assert hasattr(result, "score_breakdown")
        assert hasattr(result, "files_scanned")
        assert hasattr(result, "target")

    def test_scan_score_range(self):
        """Score should be between 0 and 100."""
        scanner = Scanner()
        result = scanner.scan(VULNERABLE)
        assert 0 <= result.score <= 100

    def test_scan_findings_sorted_by_severity(self):
        """Findings should be sorted with CRITICAL first."""
        scanner = Scanner()
        result = scanner.scan(VULNERABLE)
        if len(result.findings) > 1:
            for i in range(len(result.findings) - 1):
                assert result.findings[i].severity >= result.findings[i + 1].severity or (
                    result.findings[i].severity == result.findings[i + 1].severity
                ), "Findings should be sorted by severity (CRITICAL first)"

    def test_severity_filter(self):
        """--severity flag should filter findings."""
        scanner = Scanner(severity_filter=[Severity.CRITICAL])
        result = scanner.scan(VULNERABLE)
        for finding in result.findings:
            assert finding.severity == Severity.CRITICAL, (
                f"Severity filter not applied: {finding.rule_id} is {finding.severity.name}"
            )

    def test_rule_id_filter(self):
        """--rule-id flag should only run specified rules."""
        scanner = Scanner(rule_ids=["SEC001"])
        result = scanner.scan(VULNERABLE)
        for finding in result.findings:
            assert finding.rule_id == "SEC001", (
                f"Rule ID filter not applied: got {finding.rule_id}"
            )

    def test_scan_single_file(self):
        """Scanner should handle scanning a single file."""
        single_file = str(FIXTURES / "vulnerable" / "secrets" / "hardcoded_openai_key.py")
        scanner = Scanner()
        result = scanner.scan(single_file)
        assert result.files_scanned == 1
        assert any(f.rule_id == "SEC001" for f in result.findings)

    def test_scan_result_to_dict(self):
        """ScanResult.to_dict() should produce a valid dictionary."""
        scanner = Scanner()
        result = scanner.scan(VULNERABLE)
        d = result.to_dict()
        assert "shipsafe_version" in d
        assert "score" in d
        assert "findings" in d
        assert "summary" in d
        assert isinstance(d["findings"], list)
        assert isinstance(d["score"]["value"], int)

    def test_nonexistent_path_returns_zero_files(self):
        """Scanning a nonexistent path should scan 0 files gracefully."""
        scanner = Scanner()
        result = scanner.scan("/nonexistent/path/that/does/not/exist")
        assert result.files_scanned == 0
