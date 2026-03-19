"""Shared application service layer for ShipSafe clients."""

from dataclasses import dataclass, field

from shipsafe.config import DEFAULT_PROFILE
from shipsafe.finding import SEVERITY_MAP, ScanResult, Severity
from shipsafe.reporters import html, json_reporter, sarif, terminal
from shipsafe.scanner import Scanner

REPORTERS = {
    "terminal": terminal.render,
    "json": json_reporter.render,
    "sarif": sarif.render,
    "html": html.render,
}


@dataclass(slots=True)
class ScanOptions:
    """Normalized scan options shared by CLI and desktop clients."""

    target: str
    profile: str = DEFAULT_PROFILE
    severity_filter: list[Severity] | None = None
    rule_ids: list[str] | None = None
    exclude_paths: list[str] | None = None
    fail_on: list[Severity] = field(
        default_factory=lambda: [Severity.CRITICAL, Severity.HIGH]
    )


def parse_severity_list(raw: str | None) -> list[Severity] | None:
    """Parse a comma-separated severity string into Severity enums."""
    if not raw:
        return None

    result = []
    for name in raw.split(","):
        normalized = name.strip().upper()
        if normalized in SEVERITY_MAP:
            result.append(SEVERITY_MAP[normalized])
    return result or None


def parse_csv_list(raw: str | None) -> list[str] | None:
    """Parse a comma-separated string into a list of non-empty values."""
    if not raw:
        return None
    items = [item.strip() for item in raw.split(",") if item.strip()]
    return items or None


def run_scan(options: ScanOptions) -> ScanResult:
    """Run a scan with normalized options."""
    scanner = Scanner(
        profile=options.profile,
        exclude_paths=options.exclude_paths,
        severity_filter=options.severity_filter,
        rule_ids=options.rule_ids,
    )
    return scanner.scan(options.target)


def render_report(result: ScanResult, output_format: str, **kwargs) -> str:
    """Render a scan result using one of ShipSafe's built-in reporters.

    Extra keyword arguments (trend_data, diff_data, suppressed_fps) are
    forwarded to the HTML renderer only.
    """
    try:
        renderer = REPORTERS[output_format]
    except KeyError as exc:
        available = ", ".join(sorted(REPORTERS))
        raise ValueError(
            f"Unsupported output format '{output_format}'. Available: {available}"
        ) from exc
    if output_format == "html" and kwargs:
        return renderer(result, **kwargs)
    return renderer(result)


def exit_code_for_result(
    result: ScanResult, fail_on: list[Severity] | None = None
) -> int:
    """Return the process exit code for a result and fail-on policy."""
    fail_severities = fail_on or [Severity.CRITICAL, Severity.HIGH]
    has_failures = any(f.severity in fail_severities for f in result.findings)
    return 1 if has_failures else 0
