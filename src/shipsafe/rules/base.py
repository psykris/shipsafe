"""Base Rule class for ShipSafe detection rules.

Every rule must declare its detection patterns as class-level constants
so they are greppable and auditable. Run this to see every pattern:

    grep -A2 "patterns = \\[" src/shipsafe/rules/*.py

Every rule must include a concrete fix and a link to an educational guide.
"""

import re
from abc import ABC, abstractmethod

from shipsafe.finding import Finding, Severity


class Rule(ABC):
    """Abstract base class for all ShipSafe detection rules.

    Subclasses must set these class attributes:
        id:          Unique identifier (e.g., "SEC001")
        name:        Human-readable name
        severity:    Default severity level
        description: What this rule detects and why it matters
        fix:         Copy-paste fix instructions
        guide_url:   Link to educational guide

    Subclasses that use regex declare patterns as class-level constants:
        patterns:    List of regex pattern strings

    Subclasses must implement:
        scan(file_path, content) -> list[Finding]
    """

    id: str = ""
    name: str = ""
    severity: Severity = Severity.MEDIUM
    description: str = ""
    fix: str = ""
    guide_url: str = ""
    owasp_id: str | None = None
    owasp_llm_id: str | None = None
    cwe_id: str | None = None
    confidence: str = "medium"  # "high", "medium", or "low"

    # Subclasses declare patterns as visible class-level constants
    patterns: list[str] = []

    # File extensions this rule applies to (empty = all text files)
    file_extensions: list[str] = []

    @abstractmethod
    def scan(self, file_path: str, content: str) -> list[Finding]:
        """Scan a file and return any findings.

        Args:
            file_path: Path to the file being scanned.
            content: Text content of the file.

        Returns:
            List of Finding objects for any detected issues.
        """
        ...

    def applies_to(self, file_path: str) -> bool:
        """Check if this rule applies to the given file path."""
        if not self.file_extensions:
            return True
        return any(file_path.endswith(ext) for ext in self.file_extensions)

    def _make_finding(
        self,
        file_path: str,
        line_number: int,
        snippet: str,
        message: str | None = None,
        fix: str | None = None,
    ) -> Finding:
        """Create a Finding with this rule's metadata."""
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            file_path=file_path,
            line_number=line_number,
            message=message or self.description,
            fix=fix or self.fix,
            snippet=snippet,
            guide_url=self.guide_url,
            owasp_id=self.owasp_id,
            owasp_llm_id=self.owasp_llm_id,
            cwe_id=self.cwe_id,
            confidence=self.confidence,
        )

    def _scan_patterns(self, file_path: str, content: str) -> list[Finding]:
        """Scan content against all patterns in self.patterns.

        This is a convenience method for rules that use regex patterns.
        Each match produces a finding with a redacted snippet.

        Lines containing ``# shipsafe-ignore`` or ``// shipsafe-ignore``
        are skipped (inline suppression for acknowledged false positives).
        """
        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            # Inline suppression — skip lines the developer has acknowledged
            if "shipsafe-ignore" in line:
                continue
            for pattern in self.patterns:
                if re.search(pattern, line):
                    findings.append(
                        self._make_finding(
                            file_path=file_path,
                            line_number=i,
                            snippet=self._redact(line, pattern),
                        )
                    )
                    break  # One finding per line max
        return findings

    def _redact(self, line: str, pattern: str) -> str:
        """Redact sensitive values matched by pattern.

        Override in subclasses for custom redaction logic.
        Default: replace matched portion with ...REDACTED.
        """
        return re.sub(pattern, "[REDACTED]", line)
