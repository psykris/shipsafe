"""Trust test: ReDoS resistance.

Verify no regex pattern exhibits catastrophic backtracking.

Why this matters
----------------
ShipSafe runs on untrusted input — the very source files it scans.  A
malicious (or just unusual) source file could contain strings crafted to
trigger catastrophic backtracking in a poorly-written regex, causing the
scanner to hang indefinitely.  This is a denial-of-service vector known
as "Regular Expression Denial of Service" (ReDoS).

Strategy
--------
1. Discover all rules and extract their ``patterns`` lists.
2. Run each pattern against a battery of adversarial inputs — long
   repeated characters, prefix-matched strings, alternation triggers,
   and multi-line payloads.
3. Assert that every match attempt completes in under 1 second.
"""

import re
import time

from shipsafe.rules import discover_rules


# Adversarial inputs designed to trigger catastrophic backtracking
# in vulnerable regex patterns.
ADVERSARIAL_INPUTS = [
    # Plain long strings
    "a" * 10_000,
    "A" * 10_000,
    "0" * 10_000,

    # Strings that match common secret prefixes but then fail to
    # complete the pattern — these are the most dangerous for
    # backtracking because the engine keeps retrying.
    "sk-" + "a" * 10_000,
    "sk-proj-" + "a" * 10_000,
    "sk-ant-api03-" + "a" * 10_000,
    "AKIA" + "A" * 10_000,
    "ghp_" + "x" * 10_000,
    "glpat-" + "x" * 10_000,
    "xoxb-" + "0" * 10_000,
    "SG." + "a" * 10_000,
    "npm_" + "a" * 10_000,
    "pypi-" + "a" * 10_000,
    "dckr_pat_" + "a" * 10_000,
    "vercel_" + "a" * 10_000,
    "AIza" + "a" * 10_000,
    "key-" + "a" * 10_000,

    # Special characters that interact badly with greedy quantifiers
    "=" * 10_000,
    " " * 10_000,
    "." * 10_000,
    '"' * 10_000,

    # Patterns that stress anchoring and alternation
    "verify" + " " * 5_000 + "=" + " " * 5_000 + "False",
    "DEBUG" + " " * 5_000 + "=" + " " * 5_000 + "True",
    "password" * 1_000,
    "console.log(" + "x" * 10_000 + ")",

    # Multi-line payloads
    "x" * 10_000 + "\n" + "y" * 10_000,
    "\n".join(["a" * 100] * 100),

    # Mixed prefix/suffix stress
    "postgres://" + "a:b@" * 2_500,
    "-----BEGIN RSA PRIVATE KEY-----" + "\n" + "x" * 10_000,
]


def test_all_patterns_resist_redos():
    """Verify no regex pattern takes >1s on adversarial input."""
    rules = discover_rules()
    assert len(rules) > 0, "No rules discovered — test setup error"

    slow_patterns: list[str] = []

    for rule in rules:
        patterns = getattr(rule, "patterns", [])
        for pattern in patterns:
            for adversarial in ADVERSARIAL_INPUTS:
                start = time.time()
                try:
                    re.search(pattern, adversarial)
                except re.error:
                    pass  # Invalid regex is caught by other tests
                elapsed = time.time() - start
                if elapsed >= 1.0:
                    slow_patterns.append(
                        f"ReDoS vulnerability: pattern {pattern[:60]!r} "
                        f"in rule {rule.id} took {elapsed:.1f}s on "
                        f"input {adversarial[:30]!r}..."
                    )

    assert slow_patterns == [], (
        "Regex patterns vulnerable to ReDoS:\n" + "\n".join(slow_patterns)
    )


def test_all_rules_have_valid_patterns():
    """Verify every pattern in every rule is a valid regex."""
    rules = discover_rules()
    invalid: list[str] = []

    for rule in rules:
        patterns = getattr(rule, "patterns", [])
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                invalid.append(f"Rule {rule.id}: pattern {pattern!r} — {exc}")

    assert invalid == [], (
        "Invalid regex patterns found:\n" + "\n".join(invalid)
    )
