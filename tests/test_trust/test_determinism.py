"""Trust test: Determinism.

Prove that running the same scan twice produces byte-identical results.

Why this matters
----------------
ShipSafe is meant to run in CI pipelines, pre-commit hooks, and
automated gating workflows.  If results are non-deterministic — e.g.
because of random ordering, timestamps, or hash maps — then developers
can't trust that a "green" run actually means "no new issues".

We test both the structured ScanResult object and the JSON reporter
output to ensure determinism at every layer.
"""

from pathlib import Path

from shipsafe.reporters import json_reporter
from shipsafe.scanner import Scanner


FIXTURES = str(Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable")


def test_scan_produces_identical_results():
    """Run the same scan twice and verify all fields match."""
    scanner = Scanner()
    result1 = scanner.scan(FIXTURES)
    result2 = scanner.scan(FIXTURES)

    # Same number of findings
    assert len(result1.findings) == len(result2.findings), (
        f"Finding count differs: {len(result1.findings)} vs {len(result2.findings)}"
    )

    # Same overall score
    assert result1.score == result2.score, (
        f"Score differs: {result1.score} vs {result2.score}"
    )

    # Every finding matches field-by-field
    for i, (f1, f2) in enumerate(zip(result1.findings, result2.findings)):
        assert f1.rule_id == f2.rule_id, (
            f"Finding {i} rule_id differs: {f1.rule_id} vs {f2.rule_id}"
        )
        assert f1.file_path == f2.file_path, (
            f"Finding {i} file_path differs: {f1.file_path} vs {f2.file_path}"
        )
        assert f1.line_number == f2.line_number, (
            f"Finding {i} line_number differs: {f1.line_number} vs {f2.line_number}"
        )
        assert f1.severity == f2.severity, (
            f"Finding {i} severity differs: {f1.severity} vs {f2.severity}"
        )
        assert f1.snippet == f2.snippet, (
            f"Finding {i} snippet differs"
        )
        assert f1.message == f2.message, (
            f"Finding {i} message differs"
        )
        assert f1.fix == f2.fix, (
            f"Finding {i} fix differs"
        )


def test_json_output_identical():
    """Verify JSON output is byte-identical across runs."""
    scanner = Scanner()

    json1 = json_reporter.render(scanner.scan(FIXTURES))
    json2 = json_reporter.render(scanner.scan(FIXTURES))

    assert json1 == json2, "JSON output is not deterministic across runs"


def test_score_breakdown_identical():
    """Verify the score breakdown dict is identical across runs."""
    scanner = Scanner()
    result1 = scanner.scan(FIXTURES)
    result2 = scanner.scan(FIXTURES)

    assert result1.score_breakdown == result2.score_breakdown, (
        "Score breakdown differs between runs"
    )


def test_findings_order_is_stable():
    """Verify findings are returned in the same order every time."""
    scanner = Scanner()
    result1 = scanner.scan(FIXTURES)
    result2 = scanner.scan(FIXTURES)

    ids1 = [(f.rule_id, f.file_path, f.line_number) for f in result1.findings]
    ids2 = [(f.rule_id, f.file_path, f.line_number) for f in result2.findings]

    assert ids1 == ids2, "Finding order is not stable between runs"
