"""Tests for the shared ShipSafe application service layer."""

from pathlib import Path

from shipsafe.finding import Finding, ScanResult, Severity
from shipsafe.reporters import html, json_reporter, sarif
from shipsafe.scanner import Scanner
from shipsafe.scoring import calculate_score
from shipsafe.service import (
    ScanOptions,
    exit_code_for_result,
    render_report,
    run_scan,
)

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = str(FIXTURES / "vulnerable")


def _sample_result() -> ScanResult:
    findings = [
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
        )
    ]
    score, breakdown = calculate_score(findings)
    return ScanResult(
        findings=findings,
        score=score,
        score_breakdown=breakdown,
        files_scanned=4,
        profile="",
        target="/repo",
    )


def test_run_scan_matches_scanner():
    """Service-layer scan results should match direct Scanner usage."""
    direct = Scanner().scan(VULNERABLE)
    via_service = run_scan(ScanOptions(target=VULNERABLE))
    assert via_service.to_dict() == direct.to_dict()


def test_render_report_matches_existing_reporters():
    """Service report rendering should delegate to the existing reporters."""
    sample_result = _sample_result()
    assert render_report(sample_result, "json") == json_reporter.render(sample_result)
    assert render_report(sample_result, "sarif") == sarif.render(sample_result)
    assert render_report(sample_result, "html") == html.render(sample_result)


def test_exit_code_for_result_defaults():
    """Exit code logic should keep the CLI semantics unchanged."""
    sample_result = _sample_result()
    clean_score, clean_breakdown = calculate_score([])
    clean_result = ScanResult(
        findings=[],
        score=clean_score,
        score_breakdown=clean_breakdown,
        files_scanned=1,
        profile="",
        target="/repo",
    )
    assert exit_code_for_result(sample_result) == 1
    assert exit_code_for_result(clean_result) == 0
