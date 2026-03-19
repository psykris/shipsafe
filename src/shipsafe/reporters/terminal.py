"""Terminal reporter — colored output with ANSI escape codes.

Uses **no external dependencies** (no ``rich``).  On Windows terminals
that do not support ANSI, colours are automatically disabled.
"""

import os
import sys

from shipsafe.finding import ScanResult, Severity
from shipsafe.scoring import score_label

# ── ANSI helpers ──────────────────────────────────────────────────────

_SUPPORTS_COLOR: bool = (
    hasattr(sys.stdout, "isatty")
    and sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM") != "dumb"
)

# On Windows, try to enable ANSI support
if _SUPPORTS_COLOR and os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        _SUPPORTS_COLOR = False

RESET = "\033[0m" if _SUPPORTS_COLOR else ""
BOLD = "\033[1m" if _SUPPORTS_COLOR else ""
DIM = "\033[2m" if _SUPPORTS_COLOR else ""

_SEV_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "\033[91m" if _SUPPORTS_COLOR else "",   # bright red
    Severity.HIGH:     "\033[93m" if _SUPPORTS_COLOR else "",   # bright yellow
    Severity.MEDIUM:   "\033[33m" if _SUPPORTS_COLOR else "",   # yellow
    Severity.LOW:      "\033[36m" if _SUPPORTS_COLOR else "",   # cyan
    Severity.INFO:     "\033[37m" if _SUPPORTS_COLOR else "",   # white
}

_SEV_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "!!",
    Severity.HIGH:     "! ",
    Severity.MEDIUM:   "- ",
    Severity.LOW:      ". ",
    Severity.INFO:     "  ",
}

_SCORE_COLORS: dict[str, str] = {
    "RED":    "\033[91m" if _SUPPORTS_COLOR else "",
    "ORANGE": "\033[33m" if _SUPPORTS_COLOR else "",
    "YELLOW": "\033[93m" if _SUPPORTS_COLOR else "",
    "GREEN":  "\033[92m" if _SUPPORTS_COLOR else "",
}


def _c(severity: Severity, text: str) -> str:
    """Wrap text in severity colour."""
    return f"{_SEV_COLORS[severity]}{text}{RESET}"


# ── Public API ────────────────────────────────────────────────────────


def render(result: ScanResult, file: object = None) -> str:
    """Render a scan result as coloured terminal text.

    Args:
        result: The completed scan result.
        file: Writable file object (defaults to sys.stdout).

    Returns:
        The rendered report as a string.
    """
    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{BOLD}ShipSafe Security Report{RESET}")
    lines.append("=" * 50)
    lines.append(f"Target:  {result.target}")
    lines.append(f"Files:   {result.files_scanned} scanned")
    lines.append("")

    # ── Score ─────────────────────────────────────────────────────────
    label_key, label_text = score_label(result.score)
    color = _SCORE_COLORS.get(label_key, "")
    lines.append(f"{BOLD}Score: {color}{result.score}/100{RESET}  {DIM}[{label_text}]{RESET}")
    lines.append("")

    # Score breakdown
    lines.append(f"  {DIM}Score breakdown:{RESET}")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        info = result.score_breakdown.get(sev.name, {})
        count = info.get("count", 0)
        weight = info.get("weight", 0)
        applied = info.get("applied_deduction", 0)
        cap = info.get("cap", 0)
        if count > 0:
            lines.append(
                f"    {_c(sev, sev.name):>22s}  "
                f"{count} x -{weight} = -{applied}"
                f"  {DIM}(cap -{cap}){RESET}"
            )
        else:
            lines.append(f"    {_c(sev, sev.name):>22s}  {DIM}0 findings{RESET}")
    lines.append("")

    # ── Findings ──────────────────────────────────────────────────────
    if not result.findings:
        lines.append(f"{BOLD}No findings.{RESET}")
        lines.append("")
        output = "\n".join(lines)
        if file:
            print(output, file=file)
        return output

    # Group by severity
    grouped: dict[Severity, list] = {}
    for f in result.findings:
        grouped.setdefault(f.severity, []).append(f)

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        findings = grouped.get(sev, [])
        if not findings:
            continue

        icon = _SEV_ICONS[sev]
        lines.append(
            f"{_c(sev, f'--- {sev.name} ({len(findings)} finding{"s" if len(findings) != 1 else ""}) ---')}"
        )
        lines.append("")

        for finding in findings:
            lines.append(f"  {_c(sev, icon)} [{finding.rule_id}] {BOLD}{finding.rule_name}{RESET}")
            lines.append(f"     File: {finding.file_path}:{finding.line_number}")
            lines.append(f"     Code: {DIM}{finding.snippet}{RESET}")
            lines.append("")
            lines.append(f"     {BOLD}Why this matters:{RESET}")
            for msg_line in finding.message.split("\n"):
                lines.append(f"       {msg_line}")
            lines.append("")
            lines.append(f"     {BOLD}Fix:{RESET}")
            for fix_line in finding.fix.split("\n"):
                lines.append(f"       {fix_line}")
            lines.append("")
            if finding.guide_url:
                lines.append(f"     {DIM}Learn more: {finding.guide_url}{RESET}")
            lines.append("")

    # ── Footer ────────────────────────────────────────────────────────
    total = len(result.findings)
    lines.append(f"{DIM}{'─' * 50}{RESET}")
    lines.append(
        f"{total} finding{'s' if total != 1 else ''} | "
        f"Score: {result.score}/100"
    )
    lines.append("")

    output = "\n".join(lines)
    if file:
        print(output, file=file)
    return output
