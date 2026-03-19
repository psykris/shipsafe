"""Trust test: Redaction.

Verify that actual secret values are NEVER exposed in scan output.

Why this matters
----------------
When ShipSafe detects a hardcoded secret, the finding's snippet, message,
and fix text must contain only a redacted placeholder — never the real
credential.  If a real key leaked into a CI log, JSON report, or terminal
output, ShipSafe would become the very vulnerability it was designed to
prevent.

Strategy
--------
1. Read each fixture file that contains a known secret.
2. Extract the actual secret value from the file content.
3. Run the scanner on the fixtures directory.
4. Assert that none of the actual secret values appear in any
   finding's snippet, message, or fix fields.
"""

import re
from pathlib import Path

from shipsafe.reporters import json_reporter
from shipsafe.scanner import Scanner


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable"
SECRETS_DIR = FIXTURES_DIR / "secrets"


def _extract_secrets_from_fixtures() -> list[str]:
    """Read fixture files and extract hardcoded secret values.

    Returns a list of raw secret strings that should NEVER appear in
    scanner output.
    """
    secrets: list[str] = []

    # Patterns to extract actual secret values from fixture files.
    # Each tuple is (filename, regex that captures the secret value).
    extraction_patterns = [
        (
            "hardcoded_openai_key.py",
            r'"(sk-proj-[a-zA-Z0-9_-]{40,})"',
        ),
        (
            "hardcoded_aws_key.py",
            r'"(AKIA[0-9A-Z]{16})"',
        ),
        (
            "hardcoded_aws_key.py",
            r'"(wJalrXUtnFEMI[^"]+)"',
        ),
        (
            "hardcoded_stripe_key.py",
            r'"(sk_live_[0-9a-zA-Z]{24,})"',
        ),
        (
            "hardcoded_github_token.py",
            r'"(ghp_[0-9a-zA-Z]{36})"',
        ),
        (
            "hardcoded_anthropic_key.py",
            r'"(sk-ant-api03-[a-zA-Z0-9_-]{40,})"',
        ),
        (
            "hardcoded_slack_token.py",
            r'"(xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+)"',
        ),
        (
            "hardcoded_db_url.py",
            r'"(postgres://[^"]+)"',
        ),
        (
            "hardcoded_db_url.py",
            r'"(mongodb://[^"]+)"',
        ),
        (
            "hardcoded_db_url.py",
            r'"(redis://[^"]+)"',
        ),
        (
            "hardcoded_sendgrid_key.py",
            r'"(SG\.[^"]+)"',
        ),
        (
            "hardcoded_gitlab_token.py",
            r'"(glpat-[^"]+)"',
        ),
        (
            "hardcoded_npm_token.py",
            r'"(npm_[^"]+)"',
        ),
        (
            "hardcoded_vercel_token.py",
            r'"(vercel_[^"]+)"',
        ),
        (
            "hardcoded_docker_token.py",
            r'"(dckr_pat_[^"]+)"',
        ),
        (
            "hardcoded_mailgun_key.py",
            r'"(key-[^"]+)"',
        ),
        (
            "hardcoded_pypi_token.py",
            r'"(pypi-[^"]+)"',
        ),
        (
            "hardcoded_twilio_key.py",
            r'"(SK[0-9a-fA-F]{32})"',
        ),
        (
            "hardcoded_gcp_key.js",
            r'"(AIza[0-9A-Za-z_-]{35})"',
        ),
    ]

    for filename, pattern in extraction_patterns:
        filepath = SECRETS_DIR / filename
        if not filepath.exists():
            continue
        content = filepath.read_text(encoding="utf-8")
        match = re.search(pattern, content)
        if match:
            secret = match.group(1)
            # Only include secrets that are long enough to be meaningful
            # (avoid matching short prefixes like "sk-" alone)
            if len(secret) > 10:
                secrets.append(secret)

    return secrets


def test_secrets_never_appear_in_findings():
    """Verify actual secret values do not appear in any finding field."""
    secrets = _extract_secrets_from_fixtures()
    assert len(secrets) > 0, "Failed to extract any secrets from fixtures"

    scanner = Scanner(profile="saas")
    result = scanner.scan(str(FIXTURES_DIR))
    assert len(result.findings) > 0, "Scanner produced no findings on vulnerable fixtures"

    violations: list[str] = []

    for finding in result.findings:
        for secret in secrets:
            # Check snippet — the most likely place for leakage
            if secret in finding.snippet:
                violations.append(
                    f"Secret leaked in snippet of {finding.rule_id} "
                    f"at {finding.file_path}:{finding.line_number}"
                )
            # Check message text
            if secret in finding.message:
                violations.append(
                    f"Secret leaked in message of {finding.rule_id} "
                    f"at {finding.file_path}:{finding.line_number}"
                )
            # Check fix text
            if secret in finding.fix:
                violations.append(
                    f"Secret leaked in fix of {finding.rule_id} "
                    f"at {finding.file_path}:{finding.line_number}"
                )

    assert violations == [], (
        "Secrets found in scanner output:\n" + "\n".join(violations)
    )


def test_secrets_never_appear_in_json_output():
    """Verify actual secret values do not appear in the JSON report."""
    secrets = _extract_secrets_from_fixtures()
    assert len(secrets) > 0, "Failed to extract any secrets from fixtures"

    scanner = Scanner(profile="saas")
    result = scanner.scan(str(FIXTURES_DIR))
    json_output = json_reporter.render(result)

    violations: list[str] = []
    for secret in secrets:
        if secret in json_output:
            violations.append(f"Secret '{secret[:12]}...' found in JSON output")

    assert violations == [], (
        "Secrets found in JSON output:\n" + "\n".join(violations)
    )


def test_redacted_markers_present():
    """Verify findings contain REDACTED markers where secrets were."""
    scanner = Scanner(profile="saas")
    result = scanner.scan(str(SECRETS_DIR))

    # Collect findings from secrets rules (SEC*)
    secret_findings = [f for f in result.findings if f.rule_id.startswith("SEC")]
    assert len(secret_findings) > 0, "No secret findings produced"

    for finding in secret_findings:
        assert "REDACTED" in finding.snippet, (
            f"Finding {finding.rule_id} at {finding.file_path}:{finding.line_number} "
            f"has no REDACTED marker in snippet: {finding.snippet!r}"
        )
