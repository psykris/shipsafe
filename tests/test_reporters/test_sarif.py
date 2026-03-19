"""Tests for the SARIF reporter."""

import json

from shipsafe.reporters import sarif


def test_render_emits_valid_sarif_document(sample_result):
    """SARIF reporter should produce the expected top-level structure."""
    data = json.loads(sarif.render(sample_result))
    run = data["runs"][0]
    assert data["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "ShipSafe"
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert len(run["results"]) == 2


def test_render_maps_severity_levels(sample_result):
    """ShipSafe severities should map cleanly to SARIF levels."""
    data = json.loads(sarif.render(sample_result))
    levels = {result["ruleId"]: result["level"] for result in data["runs"][0]["results"]}
    assert levels["AI007"] == "error"
    assert levels["DEP104"] == "note"


def test_render_is_deterministic(sample_result):
    """SARIF output should be byte-stable."""
    output1 = sarif.render(sample_result)
    output2 = sarif.render(sample_result)
    assert output1 == output2


def test_render_information_uri_is_pypi(sample_result):
    """informationUri should point to the PyPI page, not a placeholder."""
    data = json.loads(sarif.render(sample_result))
    uri = data["runs"][0]["tool"]["driver"]["informationUri"]
    assert "pypi.org" in uri
    assert "github.com/user" not in uri


def test_render_artifact_uris_use_forward_slashes(sample_result):
    """Artifact location URIs must use forward slashes (valid URI references)."""
    data = json.loads(sarif.render(sample_result))
    for result in data["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "\\" not in uri, f"Backslash found in URI: {uri!r}"


def test_render_absolute_path_becomes_file_uri(tmp_path):
    """An absolute file path should be converted to a file:// URI."""
    from shipsafe.finding import Finding, ScanResult, Severity
    from shipsafe.scoring import calculate_score

    abs_path = str(tmp_path / "src" / "app.py")
    finding = Finding(
        rule_id="SEC001",
        rule_name="Test rule",
        severity=Severity.HIGH,
        file_path=abs_path,
        line_number=1,
        message="msg",
        fix="fix",
        snippet="code",
        guide_url="",
    )
    score, breakdown = calculate_score([finding])
    result = ScanResult(
        findings=[finding],
        score=score,
        score_breakdown=breakdown,
        files_scanned=1,
        profile="saas",
        target=str(tmp_path),
    )
    data = json.loads(sarif.render(result))
    uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("file:///"), f"Expected file:// URI, got: {uri!r}"
    assert "\\" not in uri
