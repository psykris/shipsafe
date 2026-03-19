"""Finding and Severity data structures for ShipSafe scan results."""

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Severity levels for security findings, ordered by impact."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


# Map severity names to enum values for profile parsing
SEVERITY_MAP: dict[str, Severity] = {s.name: s for s in Severity}


@dataclass
class Finding:
    """A single security finding from a scan rule."""

    rule_id: str
    rule_name: str
    severity: Severity
    file_path: str
    line_number: int
    message: str
    fix: str
    snippet: str
    guide_url: str
    owasp_id: str | None = None
    owasp_llm_id: str | None = None
    cwe_id: str | None = None
    confidence: str = "medium"  # "high", "medium", or "low"
    fingerprint: str = ""

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary for JSON output."""
        d: dict = {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "message": self.message,
            "fix": self.fix,
            "snippet": self.snippet,
            "guide_url": self.guide_url,
            "owasp_id": self.owasp_id,
            "owasp_llm_id": self.owasp_llm_id,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence,
        }
        if self.fingerprint:
            d["fingerprint"] = self.fingerprint
        return d


@dataclass
class ScanResult:
    """Complete result from a ShipSafe scan."""

    findings: list[Finding]
    score: int
    score_breakdown: dict
    files_scanned: int
    profile: str
    target: str

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary for JSON output."""
        from shipsafe import __version__

        return {
            "shipsafe_version": __version__,
            "target": self.target,
            "profile": self.profile,
            "files_scanned": self.files_scanned,
            "score": {
                "value": self.score,
                "breakdown": self.score_breakdown,
            },
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            },
        }
