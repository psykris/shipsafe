"""SARIF reporter for code scanning integrations."""

import json
from pathlib import Path

from shipsafe import __version__
from shipsafe.finding import Finding, ScanResult, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

SARIF_LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _to_uri(file_path: str) -> str:
    """Convert a file path to a URI suitable for SARIF.

    Absolute paths become ``file:///`` URIs.  Relative paths are normalised
    to forward-slash notation so they remain valid URI references on Windows.
    """
    p = Path(file_path)
    if p.is_absolute():
        return p.as_uri()
    return file_path.replace("\\", "/")


def _rule_properties(finding: Finding) -> dict[str, str]:
    """Build SARIF rule properties for a finding."""
    properties = {
        "severity": finding.severity.name,
        "security-severity": SECURITY_SEVERITY[finding.severity],
    }
    if finding.owasp_id:
        properties["owasp"] = finding.owasp_id
    if finding.owasp_llm_id:
        properties["owasp-llm"] = finding.owasp_llm_id
    return properties


def _rule_descriptor(finding: Finding) -> dict:
    """Create a SARIF rule descriptor from a ShipSafe finding."""
    descriptor = {
        "id": finding.rule_id,
        "name": finding.rule_name,
        "shortDescription": {"text": finding.rule_name},
        "fullDescription": {"text": finding.message},
        "help": {"text": finding.fix},
        "defaultConfiguration": {"level": SARIF_LEVELS[finding.severity]},
        "properties": _rule_properties(finding),
    }
    if finding.guide_url:
        descriptor["helpUri"] = finding.guide_url
    if finding.cwe_id:
        # SARIF standard: relationships with CWE taxonomy
        cwe_num = finding.cwe_id.replace("CWE-", "")
        descriptor["relationships"] = [{
            "target": {
                "id": cwe_num,
                "guid": "",
                "toolComponent": {"name": "CWE", "guid": ""},
            },
            "kinds": ["superset"],
        }]
        descriptor["properties"]["cwe"] = finding.cwe_id
    return descriptor


def _result_entry(finding: Finding) -> dict:
    """Create a SARIF result entry from a ShipSafe finding."""
    properties = {
        "severity": finding.severity.name,
        "guideUrl": finding.guide_url,
        "recommendedFix": finding.fix,
        "snippet": finding.snippet,
    }
    if finding.owasp_id:
        properties["owasp"] = finding.owasp_id
    if finding.owasp_llm_id:
        properties["owasp-llm"] = finding.owasp_llm_id
    if finding.cwe_id:
        properties["cwe"] = finding.cwe_id
    if finding.fingerprint:
        properties["fingerprint"] = finding.fingerprint
    properties["confidence"] = finding.confidence

    return {
        "ruleId": finding.rule_id,
        "level": SARIF_LEVELS[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _to_uri(finding.file_path)},
                    "region": {
                        "startLine": finding.line_number,
                        "snippet": {"text": finding.snippet},
                    },
                }
            }
        ],
        "properties": properties,
    }


def render(result: ScanResult, indent: int = 2) -> str:
    """Render a scan result as a SARIF 2.1.0 document."""
    rules_by_id: dict[str, Finding] = {}
    for finding in result.findings:
        rules_by_id.setdefault(finding.rule_id, finding)

    sarif_document = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ShipSafe",
                        "version": __version__,
                        "informationUri": "https://pypi.org/project/shipsafe/",
                        "rules": [
                            _rule_descriptor(rules_by_id[rule_id])
                            for rule_id in sorted(rules_by_id)
                        ],
                    }
                },
                "automationDetails": {"id": "shipsafe"},
                "properties": {
                    "target": result.target,
                    "filesScanned": result.files_scanned,
                    "score": result.score,
                    "scoreBreakdown": result.score_breakdown,
                },
                "results": [_result_entry(finding) for finding in result.findings],
            }
        ],
    }
    return json.dumps(sarif_document, indent=indent, ensure_ascii=False)
