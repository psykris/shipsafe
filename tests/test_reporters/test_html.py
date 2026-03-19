"""Tests for the HTML reporter."""

import re

from shipsafe.reporters import html


def test_render_emits_full_document(sample_result):
    """HTML reporter should emit a standalone document."""
    output = html.render(sample_result)
    assert "<!DOCTYPE html>" in output
    assert "ShipSafe Security Report" in output
    assert "Missing HTML sanitization for model output" in output


def test_render_escapes_snippets(sample_result):
    """HTML reporter must prevent </script> injection in embedded JSON."""
    output = html.render(sample_result)
    # The snippet is embedded as JSON; </script> must be escaped to <\/script>
    # so that a malicious snippet cannot break out of the <script> block.
    assert "alert(1)" in output  # snippet data is present
    assert "<script>alert(1)</script>" not in output  # raw form safely encoded


def test_render_handles_no_findings(clean_result):
    """HTML reporter should show a branded clean empty state."""
    output = html.render(clean_result)
    assert "Clean scan" in output
    assert "no findings" in output
    assert "success-icon" in output


def test_render_includes_timestamp(sample_result):
    """HTML report should embed a UTC scan timestamp."""
    output = html.render(sample_result)
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", output)


def test_render_includes_version(sample_result):
    """HTML report should embed the ShipSafe version number."""
    from shipsafe import __version__

    output = html.render(sample_result)
    assert f"v{__version__}" in output


def test_render_severity_pill_colors(sample_result):
    """Each severity level should have a corresponding CSS colour rule."""
    output = html.render(sample_result)
    # Phase 5 uses severity dot + class approach (.sev-high, .sev-dot.high)
    assert ".sev-high" in output
    assert ".sev-low" in output


def test_render_fix_text_preserves_newlines(sample_findings):
    """Multi-line fix text must not be collapsed — _fmt() inserts <br>."""
    from shipsafe.finding import ScanResult, Severity, Finding
    from shipsafe.scoring import calculate_score

    multiline_finding = Finding(
        rule_id="SEC001",
        rule_name="Test rule",
        severity=Severity.HIGH,
        file_path="app.py",
        line_number=1,
        message="Something bad.",
        fix="Step 1: do this.\nStep 2: do that.\nStep 3: verify.",
        snippet="bad_code()",
        guide_url="",
    )
    score, breakdown = calculate_score([multiline_finding])
    result = ScanResult(
        findings=[multiline_finding],
        score=score,
        score_breakdown=breakdown,
        files_scanned=1,
        profile="",
        target="/repo",
    )
    output = html.render(result)
    assert "<br>" in output
    assert "pre-text" in output


def test_render_owasp_ids_are_links(sample_result):
    """OWASP URLs should be present in the report for JS-rendered links."""
    output = html.render(sample_result)
    # Phase 5 embeds OWASP URLs in the findings JSON data; the URL appears
    # as a data value so the JS can render a clickable link in the detail row.
    assert "https://owasp.org/Top10/A03_2021" in output


def test_render_owasp_llm_ids_are_links(sample_result):
    """OWASP LLM IDs should link to the LLM Top-10 project page."""
    output = html.render(sample_result)
    assert "owasp.org/www-project-top-10-for-large-language-model" in output


def test_render_includes_print_css(sample_result):
    """Report should contain @media print rules for PDF export."""
    output = html.render(sample_result)
    assert "@media print" in output
    assert "print-btn" in output


def test_render_includes_download_json_button(sample_result):
    """Report should include a Download JSON button (replaced Save-as-PDF)."""
    output = html.render(sample_result)
    assert "downloadJSON()" in output
    assert "Download JSON" in output


def test_render_includes_sticky_header(sample_result):
    """Report should include a sticky header bar with project name."""
    output = html.render(sample_result)
    assert "report-header" in output
    assert "Security Report" in output


def test_render_score_breakdown_headers(sample_result):
    """Score breakdown table must use descriptive, human-readable headers."""
    output = html.render(sample_result)
    assert "Penalty / finding" in output
    assert "Points deducted" in output
    assert "<th>Weight</th>" not in output
    assert "<th>Applied deduction</th>" not in output
