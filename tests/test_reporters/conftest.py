"""Fixtures shared across reporter tests."""

import pytest

from shipsafe.finding import Finding, ScanResult, Severity
from shipsafe.scoring import calculate_score


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Representative findings across multiple severities."""
    return [
        Finding(
            rule_id="AI007",
            rule_name="Missing HTML sanitization for model output",
            severity=Severity.HIGH,
            file_path="src/ui.jsx",
            line_number=18,
            message="Model output reaches the DOM without sanitization.",
            fix="Sanitize or escape model output before rendering.",
            snippet='container.innerHTML = "<script>alert(1)</script>"',
            guide_url="guides/09-ai-security.md",
            owasp_id="A03:2021",
            owasp_llm_id="LLM02:2025",
        ),
        Finding(
            rule_id="DEP104",
            rule_name="Wildcard dependency version",
            severity=Severity.LOW,
            file_path="requirements.txt",
            line_number=4,
            message="Wildcard dependency specifier allows unreviewed versions.",
            fix="Pin the dependency to a reviewed version.",
            snippet="requests>=*",
            guide_url="guides/07-dependency-safety.md",
            owasp_id="A08:2021",
        ),
    ]


@pytest.fixture
def sample_result(sample_findings: list[Finding]) -> ScanResult:
    """ScanResult built from the shared sample findings."""
    score, breakdown = calculate_score(sample_findings)
    return ScanResult(
        findings=sample_findings,
        score=score,
        score_breakdown=breakdown,
        files_scanned=12,
        profile="",
        target="/repo",
    )


@pytest.fixture
def clean_result() -> ScanResult:
    """ScanResult with no findings for empty-state tests."""
    score, breakdown = calculate_score([])
    return ScanResult(
        findings=[],
        score=score,
        score_breakdown=breakdown,
        files_scanned=3,
        profile="",
        target="/repo",
    )
