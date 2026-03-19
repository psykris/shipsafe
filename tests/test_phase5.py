"""Tests for Phase 5 features: fingerprinting, history, suppress, CWE, confidence, CLI."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from shipsafe.finding import Finding, ScanResult, Severity
from shipsafe.fingerprint import fingerprint_finding, short_fingerprint
from shipsafe.scoring import calculate_score


# ═══════════════════════════════════════════════════════════════════
# Fingerprinting
# ═══════════════════════════════════════════════════════════════════


class TestFingerprinting:
    """Test stable fingerprint generation."""

    def test_basic_fingerprint(self):
        fp = fingerprint_finding("src/auth/token.ts", "SEC001", "const key = 'abc123'")
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA-256 hex digest

    def test_same_input_same_output(self):
        fp1 = fingerprint_finding("src/main.py", "SEC001", "api_key = 'test'")
        fp2 = fingerprint_finding("src/main.py", "SEC001", "api_key = 'test'")
        assert fp1 == fp2

    def test_different_rule_different_fingerprint(self):
        fp1 = fingerprint_finding("src/main.py", "SEC001", "api_key = 'test'")
        fp2 = fingerprint_finding("src/main.py", "SEC002", "api_key = 'test'")
        assert fp1 != fp2

    def test_different_file_different_fingerprint(self):
        fp1 = fingerprint_finding("src/a.py", "SEC001", "api_key = 'test'")
        fp2 = fingerprint_finding("src/b.py", "SEC001", "api_key = 'test'")
        assert fp1 != fp2

    def test_path_normalization(self):
        """Backslash and forward slash produce same fingerprint."""
        fp1 = fingerprint_finding("src\\auth\\token.py", "SEC001", "key = 'x'")
        fp2 = fingerprint_finding("src/auth/token.py", "SEC001", "key = 'x'")
        assert fp1 == fp2

    def test_leading_dot_slash_stripped(self):
        fp1 = fingerprint_finding("./src/main.py", "SEC001", "key = 'x'")
        fp2 = fingerprint_finding("src/main.py", "SEC001", "key = 'x'")
        assert fp1 == fp2

    def test_whitespace_normalization(self):
        fp1 = fingerprint_finding("a.py", "SEC001", "  key  =  'x'  ")
        fp2 = fingerprint_finding("a.py", "SEC001", "key = 'x'")
        assert fp1 == fp2

    def test_short_fingerprint(self):
        fp = fingerprint_finding("a.py", "SEC001", "x")
        assert short_fingerprint(fp) == fp[:12]
        assert short_fingerprint(fp, 8) == fp[:8]


# ═══════════════════════════════════════════════════════════════════
# History
# ═══════════════════════════════════════════════════════════════════


def _make_result(n_findings: int = 2, score: int = 80) -> ScanResult:
    """Create a minimal ScanResult for testing."""
    findings = []
    for i in range(n_findings):
        f = Finding(
            rule_id=f"SEC{i+1:03d}",
            rule_name=f"Test Rule {i+1}",
            severity=Severity.HIGH,
            file_path=f"src/file{i}.py",
            line_number=10 + i,
            message="Test message",
            fix="Test fix",
            snippet=f"vulnerable_line_{i}",
            guide_url="guides/test.md",
            fingerprint=fingerprint_finding(f"src/file{i}.py", f"SEC{i+1:03d}", f"vulnerable_line_{i}"),
        )
        findings.append(f)
    _, breakdown = calculate_score(findings)
    return ScanResult(
        findings=findings,
        score=score,
        score_breakdown=breakdown,
        files_scanned=10,
        profile="",
        target="/test/project",
    )


class TestHistory:
    """Test scan history persistence and diff."""

    def test_save_and_load(self, tmp_path):
        from shipsafe.history import list_scans, load_scan, save_scan
        result = _make_result()
        path = save_scan(result, project_root=str(tmp_path))
        assert path.exists()
        assert path.suffix == ".json"

        scans = list_scans(str(tmp_path))
        assert len(scans) == 1

        data = load_scan(scans[0])
        assert "findings" in data
        assert "_meta" in data
        assert "fingerprints" in data["_meta"]

    def test_load_latest(self, tmp_path):
        from shipsafe.history import load_latest, save_scan
        r1 = _make_result(1)
        r2 = _make_result(2)
        save_scan(r1, project_root=str(tmp_path))
        save_scan(r2, project_root=str(tmp_path))

        latest = load_latest(str(tmp_path), count=1)
        assert len(latest) == 1
        assert len(latest[0]["findings"]) == 2  # The second scan

    def test_diff_scans(self, tmp_path):
        from shipsafe.history import diff_scans, load_latest, save_scan
        r1 = _make_result(2)
        r2 = _make_result(3)  # One more finding
        save_scan(r1, project_root=str(tmp_path))
        save_scan(r2, project_root=str(tmp_path))

        scans = load_latest(str(tmp_path), count=2)
        changes = diff_scans(scans[1], scans[0])
        assert isinstance(changes["new"], set)
        assert isinstance(changes["resolved"], set)
        assert isinstance(changes["persistent"], set)

    def test_diff_no_previous(self):
        from shipsafe.history import diff_scans
        result = _make_result()
        data = result.to_dict()
        data["_meta"] = {"fingerprints": [f.fingerprint for f in result.findings]}
        changes = diff_scans(None, data)
        assert len(changes["new"]) == 2
        assert len(changes["resolved"]) == 0

    def test_score_trend(self, tmp_path):
        from shipsafe.history import save_scan, score_trend
        for _ in range(3):
            save_scan(_make_result(), project_root=str(tmp_path))
        trend = score_trend(str(tmp_path))
        assert len(trend) == 3
        assert all("date" in t and "score" in t for t in trend)


# ═══════════════════════════════════════════════════════════════════
# Suppress
# ═══════════════════════════════════════════════════════════════════


class TestSuppress:
    """Test finding suppression."""

    def test_add_suppression(self, tmp_path):
        from shipsafe.suppress import add_suppression, load_suppressions
        add_suppression("abc123", "Test fixture", "tester", str(tmp_path))
        entries = load_suppressions(str(tmp_path))
        assert len(entries) == 1
        assert entries[0]["fingerprint"] == "abc123"
        assert entries[0]["reason"] == "Test fixture"

    def test_no_duplicate_suppression(self, tmp_path):
        from shipsafe.suppress import add_suppression, load_suppressions
        add_suppression("abc123", "first", "", str(tmp_path))
        add_suppression("abc123", "second", "", str(tmp_path))
        entries = load_suppressions(str(tmp_path))
        assert len(entries) == 1

    def test_remove_suppression(self, tmp_path):
        from shipsafe.suppress import add_suppression, load_suppressions, remove_suppression
        add_suppression("abc123", "test", "", str(tmp_path))
        removed = remove_suppression("abc123", str(tmp_path))
        assert removed is True
        assert load_suppressions(str(tmp_path)) == []

    def test_is_suppressed(self, tmp_path):
        from shipsafe.suppress import add_suppression, is_suppressed
        assert is_suppressed("abc", str(tmp_path)) is False
        add_suppression("abc", "test", "", str(tmp_path))
        assert is_suppressed("abc", str(tmp_path)) is True

    def test_suppressed_fingerprints(self, tmp_path):
        from shipsafe.suppress import add_suppression, suppressed_fingerprints
        add_suppression("fp1", "r1", "", str(tmp_path))
        add_suppression("fp2", "r2", "", str(tmp_path))
        fps = suppressed_fingerprints(str(tmp_path))
        assert fps == {"fp1", "fp2"}

    def test_empty_file(self, tmp_path):
        from shipsafe.suppress import load_suppressions
        assert load_suppressions(str(tmp_path)) == []


# ═══════════════════════════════════════════════════════════════════
# Finding dataclass updates
# ═══════════════════════════════════════════════════════════════════


class TestFindingUpdates:
    """Test new fields on Finding dataclass."""

    def test_cwe_id_field(self):
        f = Finding(
            rule_id="SEC001", rule_name="Test", severity=Severity.CRITICAL,
            file_path="a.py", line_number=1, message="m", fix="f",
            snippet="s", guide_url="g", cwe_id="CWE-798",
        )
        assert f.cwe_id == "CWE-798"
        d = f.to_dict()
        assert d["cwe_id"] == "CWE-798"

    def test_confidence_field(self):
        f = Finding(
            rule_id="SEC001", rule_name="Test", severity=Severity.CRITICAL,
            file_path="a.py", line_number=1, message="m", fix="f",
            snippet="s", guide_url="g", confidence="high",
        )
        assert f.confidence == "high"
        d = f.to_dict()
        assert d["confidence"] == "high"

    def test_fingerprint_field(self):
        f = Finding(
            rule_id="SEC001", rule_name="Test", severity=Severity.CRITICAL,
            file_path="a.py", line_number=1, message="m", fix="f",
            snippet="s", guide_url="g", fingerprint="abc123",
        )
        d = f.to_dict()
        assert d["fingerprint"] == "abc123"

    def test_default_confidence(self):
        f = Finding(
            rule_id="SEC001", rule_name="Test", severity=Severity.CRITICAL,
            file_path="a.py", line_number=1, message="m", fix="f",
            snippet="s", guide_url="g",
        )
        assert f.confidence == "medium"

    def test_fingerprint_not_in_dict_when_empty(self):
        f = Finding(
            rule_id="SEC001", rule_name="Test", severity=Severity.CRITICAL,
            file_path="a.py", line_number=1, message="m", fix="f",
            snippet="s", guide_url="g",
        )
        d = f.to_dict()
        assert "fingerprint" not in d


# ═══════════════════════════════════════════════════════════════════
# Scanner fingerprint integration
# ═══════════════════════════════════════════════════════════════════


class TestScannerFingerprints:
    """Test that the scanner assigns fingerprints to findings."""

    def test_findings_have_fingerprints(self):
        from shipsafe.scanner import Scanner
        vuln_dir = Path(__file__).parent / "fixtures" / "vulnerable" / "secrets"
        if not vuln_dir.exists():
            pytest.skip("Fixture directory not found")
        scanner = Scanner()
        result = scanner.scan(str(vuln_dir))
        for finding in result.findings:
            assert finding.fingerprint, f"Finding {finding.rule_id} missing fingerprint"
            assert len(finding.fingerprint) == 64


# ═══════════════════════════════════════════════════════════════════
# HTML Reporter
# ═══════════════════════════════════════════════════════════════════


class TestHTMLReporter:
    """Test the upgraded HTML reporter."""

    def test_basic_render(self):
        from shipsafe.reporters.html import render
        result = _make_result()
        html = render(result)
        assert "<!DOCTYPE html>" in html
        assert "ShipSafe" in html
        assert "Security Score" in html

    def test_dark_mode_vars(self):
        from shipsafe.reporters.html import render
        result = _make_result()
        html = render(result)
        assert "--bg: #1A1D23" in html  # Dark mode default (softened)

    def test_light_mode_vars(self):
        from shipsafe.reporters.html import render
        result = _make_result()
        html = render(result)
        assert '[data-theme="light"]' in html

    def test_findings_json_embedded(self):
        from shipsafe.reporters.html import render
        result = _make_result()
        html = render(result)
        assert "const FINDINGS" in html

    def test_trend_data(self):
        from shipsafe.reporters.html import render
        result = _make_result()
        trend = [{"date": "2026-03-10", "score": 75}, {"date": "2026-03-11", "score": 80}]
        html = render(result, trend_data=trend)
        assert "trend-svg" in html

    def test_diff_data(self):
        from shipsafe.reporters.html import render
        result = _make_result()
        diff = {"new": {"fp1"}, "resolved": {"fp2"}, "persistent": {"fp3"}}
        html = render(result, diff_data=diff)
        assert "1 New" in html
        assert "1 Resolved" in html

    def test_empty_result(self):
        from shipsafe.reporters.html import render
        result = ScanResult(
            findings=[], score=100, score_breakdown={},
            files_scanned=5, profile="", target="/test",
        )
        html = render(result)
        assert "Clean scan" in html

    def test_filter_controls_present(self):
        from shipsafe.reporters.html import render
        result = _make_result()
        html = render(result)
        assert "filter-severity" in html
        assert "filter-confidence" in html
        assert "filter-search" in html

    def test_score_chip_has_context(self):
        from shipsafe.reporters.html import render
        result = _make_result()
        html = render(result)
        assert "/100" in html  # Score denominator


# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════


class TestCLIPhase5:
    """Test new CLI commands and flags."""

    def test_diff_no_history(self):
        from shipsafe.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            code = main(["diff", "--project-root", tmp])
            assert code == 2

    def test_trend_no_history(self):
        from shipsafe.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            code = main(["trend", "--project-root", tmp])
            assert code == 2

    def test_suppress_command(self):
        from shipsafe.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            code = main([
                "suppress", "abc123def456",
                "--reason", "Test suppression",
                "--project-root", tmp,
            ])
            assert code == 0
            suppress_file = Path(tmp) / ".shipsafe" / "suppress.json"
            assert suppress_file.exists()

    def test_scan_with_history(self):
        from shipsafe.cli import main
        vuln_dir = Path(__file__).parent / "fixtures" / "vulnerable" / "secrets"
        if not vuln_dir.exists():
            pytest.skip("Fixture directory not found")
        with tempfile.TemporaryDirectory() as tmp:
            code = main([
                "scan", str(vuln_dir),
                "--history", "--project-root", tmp,
                "--format", "json",
            ])
            history_dir = Path(tmp) / ".shipsafe" / "history"
            assert history_dir.exists()
            assert len(list(history_dir.glob("*.json"))) == 1


# ═══════════════════════════════════════════════════════════════════
# Serve (unit test only — don't actually start server)
# ═══════════════════════════════════════════════════════════════════


class TestServe:
    """Test serve utility functions."""

    def test_save_report_html(self, tmp_path):
        from shipsafe.serve import save_report_html
        html = "<html><body>test</body></html>"
        path = save_report_html(html, str(tmp_path))
        assert path.exists()
        assert path.read_text() == html

    def test_find_latest_report(self, tmp_path):
        from shipsafe.serve import _find_latest_report, save_report_html
        assert _find_latest_report(str(tmp_path)) is None
        save_report_html("<html>test</html>", str(tmp_path))
        found = _find_latest_report(str(tmp_path))
        assert found is not None
        assert found.name == "latest-report.html"
