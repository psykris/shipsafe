"""Tests for the ShipSafe scoring algorithm (src/shipsafe/scoring.py)."""

import pytest

from shipsafe.finding import Finding, Severity
from shipsafe.scoring import calculate_score, score_label


def _make_finding(severity: Severity) -> Finding:
    """Create a minimal Finding with the given severity for scoring tests."""
    return Finding(
        rule_id="TEST001",
        rule_name="Test",
        severity=severity,
        file_path="test.py",
        line_number=1,
        message="test",
        fix="fix",
        snippet="code",
        guide_url="guide.md",
    )


class TestCalculateScore:
    """Tests for calculate_score()."""

    def test_perfect_score_no_findings(self):
        """Empty findings list should yield a perfect score of 100."""
        score, breakdown = calculate_score([])
        assert score == 100

    def test_single_critical(self):
        """One CRITICAL finding should deduct 25 points: 100 - 25 = 75."""
        findings = [_make_finding(Severity.CRITICAL)]
        score, breakdown = calculate_score(findings)
        assert score == 75

    def test_critical_cap(self):
        """Four CRITICALs should be capped at -75 (not -100), giving score 25."""
        findings = [_make_finding(Severity.CRITICAL) for _ in range(4)]
        score, breakdown = calculate_score(findings)
        # 4 * 25 = 100, but cap is 75, so score = 100 - 75 = 25
        assert score == 25

    def test_mixed_severities(self):
        """1 CRITICAL + 1 HIGH + 1 MEDIUM = 100 - 25 - 10 - 5 = 60."""
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
        ]
        score, breakdown = calculate_score(findings)
        assert score == 60

    def test_minimum_score_is_zero(self):
        """Massive number of findings should floor the score at 0, never negative."""
        findings = (
            [_make_finding(Severity.CRITICAL) for _ in range(10)]
            + [_make_finding(Severity.HIGH) for _ in range(10)]
            + [_make_finding(Severity.MEDIUM) for _ in range(10)]
            + [_make_finding(Severity.LOW) for _ in range(10)]
        )
        score, breakdown = calculate_score(findings)
        assert score == 0

    def test_info_findings_no_deduction(self):
        """INFO severity findings should not reduce the score at all."""
        findings = [_make_finding(Severity.INFO) for _ in range(20)]
        score, breakdown = calculate_score(findings)
        assert score == 100


class TestScoreLabel:
    """Tests for score_label()."""

    def test_score_label_green(self):
        """Score of 95 should produce GREEN / Ready to deploy."""
        label, description = score_label(95)
        assert label == "GREEN"
        assert description == "Ready to deploy"

    def test_score_label_yellow(self):
        """Score of 75 should produce YELLOW."""
        label, description = score_label(75)
        assert label == "YELLOW"
        assert "HIGH" in description

    def test_score_label_orange(self):
        """Score of 50 should produce ORANGE."""
        label, description = score_label(50)
        assert label == "ORANGE"
        assert "security issues" in description.lower()

    def test_score_label_red(self):
        """Score of 20 should produce RED."""
        label, description = score_label(20)
        assert label == "RED"
        assert "critical" in description.lower() or "Critical" in description
