"""
ShipSafe Scoring Algorithm
==========================

Score = 100 - sum(deductions)

Deductions per severity:
    CRITICAL: -25 each, capped at -75
    HIGH:     -10 each, capped at -40
    MEDIUM:    -5 each, capped at -25
    LOW:       -2 each, capped at -10

Minimum score: 0

The cap per severity prevents a single category from zeroing out the score,
ensuring users always see progress when fixing issues in other categories.

This file is intentionally simple and self-contained so that anyone can
audit the scoring logic.
"""

from shipsafe.finding import Finding, Severity

# Deduction weights and caps — all visible, nothing hidden
DEDUCTION_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

DEDUCTION_CAPS: dict[Severity, int] = {
    Severity.CRITICAL: 75,
    Severity.HIGH: 40,
    Severity.MEDIUM: 25,
    Severity.LOW: 10,
    Severity.INFO: 0,
}


def calculate_score(findings: list[Finding]) -> tuple[int, dict]:
    """Calculate security score from findings.

    Returns:
        A tuple of (score, breakdown) where breakdown is a dict showing
        the count and deduction for each severity level.
    """
    counts: dict[str, int] = {}
    for severity in Severity:
        counts[severity.name] = sum(1 for f in findings if f.severity == severity)

    breakdown: dict[str, dict] = {}
    total_deduction = 0

    for severity in Severity:
        count = counts[severity.name]
        weight = DEDUCTION_WEIGHTS[severity]
        cap = DEDUCTION_CAPS[severity]
        raw_deduction = count * weight
        capped_deduction = min(raw_deduction, cap)
        total_deduction += capped_deduction

        breakdown[severity.name] = {
            "count": count,
            "weight": weight,
            "raw_deduction": raw_deduction,
            "cap": cap,
            "applied_deduction": capped_deduction,
        }

    score = max(0, 100 - total_deduction)

    return score, breakdown


def score_label(score: int) -> tuple[str, str]:
    """Return (emoji, label) for a score threshold.

    Thresholds:
        90-100: Ready to deploy
        70-89:  Fix HIGH items before deploying
        40-69:  Significant security issues. Do not deploy to production.
        0-39:   Critical vulnerabilities. Stop and fix before shipping.
    """
    if score >= 90:
        return "GREEN", "Ready to deploy"
    elif score >= 70:
        return "YELLOW", "Fix HIGH items before deploying"
    elif score >= 40:
        return "ORANGE", "Significant security issues. Do not deploy to production."
    else:
        return "RED", "Critical vulnerabilities. Stop and fix before shipping."
