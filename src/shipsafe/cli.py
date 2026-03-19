"""ShipSafe command-line interface.

Uses ``argparse`` only (stdlib).  No Click, no Typer, no external deps.

Exit codes
----------
0  No findings above the fail threshold
1  Findings found above the fail threshold
2  Runtime error (bad arguments, missing profile, etc.)
"""

import argparse
import sys

from shipsafe import __version__
from shipsafe.config import AVAILABLE_PROFILES, DEFAULT_PROFILE
from shipsafe.finding import Severity
from shipsafe.service import (
    REPORTERS,
    ScanOptions,
    exit_code_for_result,
    parse_csv_list,
    parse_severity_list,
    render_report,
    run_scan,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shipsafe",
        description=(
            "Deterministic security scanner for AI-generated codebases. "
            "Your code never leaves your machine."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"shipsafe {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command")

    # ── shipsafe scan ─────────────────────────────────────────────────
    scan_p = subparsers.add_parser(
        "scan", help="Scan a directory for security vulnerabilities"
    )
    scan_p.add_argument("path", help="Path to scan (file or directory)")
    scan_p.add_argument(
        "--profile",
        choices=AVAILABLE_PROFILES,
        default=DEFAULT_PROFILE,
        help=f"Scan profile (default: {DEFAULT_PROFILE})",
    )
    scan_p.add_argument(
        "--format",
        choices=tuple(REPORTERS),
        default="terminal",
        dest="output_format",
        help="Output format (default: terminal)",
    )
    scan_p.add_argument(
        "--output", "-o",
        help="Write report to file instead of stdout",
    )
    scan_p.add_argument(
        "--severity",
        help="Filter by severity: comma-separated (e.g., critical,high)",
    )
    scan_p.add_argument(
        "--rule-id",
        help="Filter by rule ID: comma-separated (e.g., SEC001,CRY001)",
    )
    scan_p.add_argument(
        "--exclude-path",
        help="Additional paths to exclude: comma-separated",
    )
    scan_p.add_argument(
        "--fail-on",
        default="critical,high",
        help="Severities that cause exit code 1 (default: critical,high)",
    )
    scan_p.add_argument(
        "--history",
        action="store_true",
        help="Save scan result to .shipsafe/history/ for trend tracking",
    )
    scan_p.add_argument(
        "--fail-new-only",
        action="store_true",
        help="Only fail on NEW findings (not pre-existing tech debt)",
    )
    scan_p.add_argument(
        "--serve",
        action="store_true",
        help="Open HTML report in browser after scan",
    )
    scan_p.add_argument(
        "--project-root",
        default=".",
        help="Project root for .shipsafe/ storage (default: current dir)",
    )

    # ── shipsafe diff ─────────────────────────────────────────────────
    diff_p = subparsers.add_parser(
        "diff", help="Show what changed since the last scan"
    )
    diff_p.add_argument(
        "--project-root",
        default=".",
        help="Project root for .shipsafe/ storage (default: current dir)",
    )

    # ── shipsafe trend ────────────────────────────────────────────────
    trend_p = subparsers.add_parser(
        "trend", help="Show score history over time"
    )
    trend_p.add_argument(
        "--project-root",
        default=".",
        help="Project root for .shipsafe/ storage (default: current dir)",
    )

    # ── shipsafe serve / ui ───────────────────────────────────────────
    serve_p = subparsers.add_parser(
        "serve", help="Launch the ShipSafe web UI in your browser"
    )
    # 'ui' is a friendly alias for 'serve'
    ui_p = subparsers.add_parser(
        "ui", help="Launch the ShipSafe web UI in your browser (alias for serve)"
    )
    for _p in (serve_p, ui_p):
        _p.add_argument(
            "--port",
            type=int,
            default=8439,
            help="Port for local server (default: 8439)",
        )
        _p.add_argument(
            "--project-root",
            default=".",
            help="Project root for .shipsafe/ storage (default: current dir)",
        )

    # ── shipsafe suppress ─────────────────────────────────────────────
    suppress_p = subparsers.add_parser(
        "suppress", help="Suppress a finding by fingerprint"
    )
    suppress_p.add_argument("fingerprint", help="Finding fingerprint to suppress")
    suppress_p.add_argument("--reason", required=True, help="Reason for suppression")
    suppress_p.add_argument("--reviewer", default="", help="Reviewer name/email")
    suppress_p.add_argument(
        "--project-root",
        default=".",
        help="Project root for .shipsafe/ storage (default: current dir)",
    )

    # ── shipsafe check-secrets ────────────────────────────────────────
    secrets_p = subparsers.add_parser(
        "check-secrets", help="Check for hardcoded secrets only"
    )
    secrets_p.add_argument("path", help="Path to scan")

    # ── shipsafe check-gitignore ──────────────────────────────────────
    git_p = subparsers.add_parser(
        "check-gitignore", help="Check .gitignore for missing entries"
    )
    git_p.add_argument("path", help="Path to scan")

    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the ``scan`` subcommand."""
    options = ScanOptions(
        target=args.path,
        profile=args.profile,
        severity_filter=parse_severity_list(args.severity),
        rule_ids=parse_csv_list(args.rule_id),
        exclude_paths=parse_csv_list(args.exclude_path),
        fail_on=parse_severity_list(args.fail_on)
        or [Severity.CRITICAL, Severity.HIGH],
    )
    result = run_scan(options)

    # ── History: save + compute trend/diff for HTML rendering ──────────
    trend_data = None
    diff_data = None
    if args.history:
        from shipsafe.history import diff_scans, load_latest, save_scan, score_trend
        saved = save_scan(result, project_root=args.project_root)
        print(f"Scan saved to {saved}", file=sys.stderr)
        trend_data = score_trend(args.project_root)
        scans = load_latest(args.project_root, count=2)
        if len(scans) >= 2:
            diff_data = diff_scans(scans[1], scans[0])

    # ── Suppressions: load for HTML badge rendering ────────────────────
    from shipsafe.suppress import suppressed_fingerprints
    suppressed_fps = suppressed_fingerprints(args.project_root)

    # ── Fail-new-only: only fail on findings not in previous scan ──────
    if args.fail_new_only:
        _diff = diff_data
        if _diff is None:
            from shipsafe.history import diff_scans, load_latest
            scans = load_latest(args.project_root, count=2)
            if len(scans) >= 2:
                _diff = diff_scans(scans[1], scans[0])
        if _diff is not None:
            new_fps = _diff["new"]
            has_new_failures = any(
                f.fingerprint in new_fps and f.severity in options.fail_on
                for f in result.findings
            )
            exit_code = 1 if has_new_failures else 0
        else:
            # No previous scan — all findings are "new"
            exit_code = exit_code_for_result(result, options.fail_on)
    else:
        exit_code = exit_code_for_result(result, options.fail_on)

    # ── Render output ──────────────────────────────────────────────────
    if args.output_format == "html":
        output = render_report(
            result, "html",
            trend_data=trend_data,
            diff_data=diff_data,
            suppressed_fps=suppressed_fps,
        )
    else:
        output = render_report(result, args.output_format)

    # Write to file or stdout
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:  # shipsafe-ignore — CLI writes to user-specified --output path
            f.write(output)
    else:
        print(output)

    # ── Serve HTML report if requested ─────────────────────────────────
    if args.serve:
        from shipsafe.serve import save_report_html, serve_report
        # Reuse already-rendered HTML when format is html, else render fresh
        html_output = output if args.output_format == "html" else render_report(
            result, "html",
            trend_data=trend_data,
            diff_data=diff_data,
            suppressed_fps=suppressed_fps,
        )
        saved = save_report_html(html_output, project_root=args.project_root)
        serve_report(html_path=saved, project_root=args.project_root)

    return exit_code


def _cmd_diff(args: argparse.Namespace) -> int:
    """Execute the ``diff`` subcommand — show changes since last scan."""
    from shipsafe.history import diff_scans, load_latest

    scans = load_latest(args.project_root, count=2)
    if len(scans) < 2:
        print("Need at least 2 scans to diff.  Run 'shipsafe scan --history' twice.")
        return 2

    current, previous = scans[0], scans[1]
    changes = diff_scans(previous, current)

    new_count = len(changes["new"])
    resolved_count = len(changes["resolved"])
    persistent_count = len(changes["persistent"])

    print(f"New findings:        {new_count}")
    print(f"Resolved findings:   {resolved_count}")
    print(f"Persistent findings: {persistent_count}")

    if changes["new"]:
        print("\n  New fingerprints:")
        for fp in sorted(changes["new"]):
            print(f"    + {fp[:12]}")

    if changes["resolved"]:
        print("\n  Resolved fingerprints:")
        for fp in sorted(changes["resolved"]):
            print(f"    - {fp[:12]}")

    return 0


def _cmd_trend(args: argparse.Namespace) -> int:
    """Execute the ``trend`` subcommand — show score history."""
    from shipsafe.history import score_trend

    trend = score_trend(args.project_root)
    if not trend:
        print("No scan history found.  Run 'shipsafe scan --history' first.")
        return 2

    print(f"Score trend ({len(trend)} scans):\n")
    for entry in trend:
        score = entry["score"]
        bar_len = score // 2  # 0-50 chars wide
        bar = "#" * bar_len
        label = _score_label_short(score)
        print(f"  {entry['date']}  {score:3d}  {bar}  {label}")

    return 0


def _score_label_short(score: int) -> str:
    """Short label for terminal trend display."""
    if score >= 90:
        return "READY"
    elif score >= 70:
        return "FIX HIGH"
    elif score >= 40:
        return "ISSUES"
    else:
        return "CRITICAL"


def _cmd_serve(args: argparse.Namespace) -> int:
    """Execute the ``serve`` subcommand."""
    from shipsafe.serve import serve_report
    serve_report(project_root=args.project_root, port=args.port)
    return 0


def _cmd_suppress(args: argparse.Namespace) -> int:
    """Execute the ``suppress`` subcommand."""
    from shipsafe.suppress import add_suppression
    path = add_suppression(
        fingerprint=args.fingerprint,
        reason=args.reason,
        reviewer=args.reviewer,
        project_root=args.project_root,
    )
    print(f"Suppressed {args.fingerprint[:12]}... — saved to {path}")
    return 0


def _cmd_check_secrets(args: argparse.Namespace) -> int:
    """Execute the ``check-secrets`` subcommand."""
    options = ScanOptions(
        target=args.path,
        profile="saas",
        rule_ids=[f"SEC{i:03d}" for i in range(1, 100)],
        fail_on=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
    )
    result = run_scan(options)
    output = render_report(result, "terminal")
    print(output)
    return 1 if result.findings else 0


def _cmd_check_gitignore(args: argparse.Namespace) -> int:
    """Execute the ``check-gitignore`` subcommand."""
    options = ScanOptions(
        target=args.path,
        profile="saas",
        rule_ids=[f"GIT{i:03d}" for i in range(1, 100)],
        fail_on=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
    )
    result = run_scan(options)
    output = render_report(result, "terminal")
    print(output)
    return 1 if result.findings else 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the ``shipsafe`` CLI."""
    # On Windows the default stdout encoding is often cp1252 which cannot
    # represent all Unicode characters in HTML/JSON/SARIF reports.
    # Reconfigure stdout to UTF-8 so output redirection (> file) works.
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    commands = {
        "scan": _cmd_scan,
        "diff": _cmd_diff,
        "trend": _cmd_trend,
        "serve": _cmd_serve,
        "ui": _cmd_serve,
        "suppress": _cmd_suppress,
        "check-secrets": _cmd_check_secrets,
        "check-gitignore": _cmd_check_gitignore,
    }

    try:
        handler = commands.get(args.command)
        if handler:
            return handler(args)
        parser.print_help()
        return 2
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
