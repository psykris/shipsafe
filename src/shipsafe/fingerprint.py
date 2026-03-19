"""Stable finding fingerprints for tracking vulnerabilities across scans.

A fingerprint is a SHA-256 hash of (normalized_file_path + rule_id +
normalized_snippet).  This remains stable even when line numbers shift
due to edits elsewhere in the file.

Usage::

    from shipsafe.fingerprint import fingerprint_finding
    fp = fingerprint_finding(finding)

The full hex digest is stored; a 12-char truncation is used for display.
"""

import hashlib


def _normalize_path(file_path: str) -> str:
    """Normalize a file path for fingerprinting.

    Converts backslashes to forward slashes, strips leading ``./``,
    and lowercases for case-insensitive filesystems.
    """
    p = file_path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lower()


def _normalize_snippet(snippet: str) -> str:
    """Normalize a code snippet for fingerprinting.

    Splits on all whitespace (handles internal runs, tabs, newlines),
    rejoins with single spaces, and lowercases.  This ensures fingerprints
    remain stable across formatting differences.
    """
    return " ".join(snippet.split()).lower()


def fingerprint_finding(
    file_path: str,
    rule_id: str,
    snippet: str,
) -> str:
    """Compute a stable fingerprint for a finding.

    Args:
        file_path: Path to the file containing the finding.
        rule_id: The rule identifier (e.g., ``SEC001``).
        snippet: The code snippet from the finding.

    Returns:
        A hex SHA-256 digest string.
    """
    parts = [
        _normalize_path(file_path),
        rule_id.strip().upper(),
        _normalize_snippet(snippet),
    ]
    payload = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def short_fingerprint(full_hash: str, length: int = 12) -> str:
    """Return a truncated fingerprint for display."""
    return full_hash[:length]
