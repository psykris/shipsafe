"""Local HTTP server for the ShipSafe web UI and reports.

Uses Python's stdlib ``http.server`` — zero external dependencies.

Serves the interactive web UI at ``/`` and all API endpoints on a
single port (default 8439).  Scan results are saved to history
automatically so that new/resolved tracking works across scans.

Usage::

    # Launch the web UI
    shipsafe serve

    # Scan and serve in one step
    shipsafe scan . --serve
"""

import http.server
import json
import os
import socketserver
import sys
import threading
import webbrowser
from pathlib import Path


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Multi-threaded HTTP server so long-running scans don't block."""
    daemon_threads = True


def _find_latest_report(project_root: str = ".") -> Path | None:
    """Find the most recent HTML report in .shipsafe/."""
    shipsafe_dir = Path(project_root).resolve() / ".shipsafe"
    if not shipsafe_dir.is_dir():
        return None

    # Check for a dedicated report file first
    report = shipsafe_dir / "latest-report.html"
    if report.is_file():
        return report

    # Fall back to the most recent HTML in the directory
    html_files = sorted(shipsafe_dir.glob("*.html"))
    return html_files[-1] if html_files else None


def _web_ui_html() -> str:
    """Read the web UI index.html from the package's web/ directory."""
    # web/ lives alongside the src/shipsafe package, two levels up
    pkg_dir = Path(__file__).resolve().parent
    web_file = pkg_dir.parent.parent / "web" / "index.html"
    if web_file.is_file():
        return web_file.read_text(encoding="utf-8")
    # Fallback: check relative to cwd
    cwd_web = Path.cwd() / "web" / "index.html"
    if cwd_web.is_file():
        return cwd_web.read_text(encoding="utf-8")
    return ""


def _rules_json() -> str:
    """Build a JSON array describing all 77 rules with metadata."""
    from shipsafe.rules import discover_rules
    rules = discover_rules()
    rows = []
    for r in sorted(rules, key=lambda x: x.id):
        rows.append({
            "id": r.id,
            "name": r.name,
            "severity": r.severity.name,
            "description": r.description,
            "fix": r.fix,
            "cwe_id": r.cwe_id or "",
            "owasp_id": r.owasp_id or "",
            "owasp_llm_id": getattr(r, "owasp_llm_id", None) or "",
            "confidence": r.confidence,
            "guide_url": r.guide_url,
            "file_extensions": r.file_extensions,
        })
    return json.dumps(rows)


def serve_report(
    html_path: Path | None = None,
    project_root: str = ".",
    port: int = 8439,
    open_browser: bool = True,
) -> None:
    """Serve the ShipSafe web UI and reports on a local HTTP server.

    Args:
        html_path: Explicit path to an HTML report file.
        project_root: Project root for finding ``.shipsafe/``.
        port: TCP port (default 8439).
        open_browser: Whether to open the default browser.
    """
    resolved_root = str(Path(project_root).resolve())

    # Pre-load the web UI HTML (patched to use correct API base)
    web_ui_content = _web_ui_html()
    if web_ui_content:
        # Ensure the API_BASE points at the same port we're running on
        web_ui_content = web_ui_content.replace(
            "const API_BASE = 'http://localhost:8439'",
            f"const API_BASE = 'http://localhost:{port}'"
        )

    # Pre-load rules JSON for the /api/rules endpoint
    rules_cache = {"json": None}

    # Resolve serve directory for static report files
    shipsafe_dir = str((Path(project_root).resolve() / ".shipsafe"))

    class Handler(http.server.SimpleHTTPRequestHandler):
        """Web UI + API handler."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=shipsafe_dir, **kwargs)

        def log_message(self, format, *args):
            pass  # Silent

        def end_headers(self):
            self.send_header("Access-Control-Allow-Origin", "*")  # shipsafe-ignore — localhost dev server only
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            super().end_headers()

        def do_OPTIONS(self):
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            if self.path in ("/", ""):
                self._serve_web_ui()
            elif self.path == "/api/info":
                self._handle_info()
            elif self.path == "/api/browse":
                self._handle_browse()
            elif self.path == "/api/rules":
                self._handle_rules()
            elif self.path == "/report":
                self._serve_latest_report()
            else:
                super().do_GET()

        def do_POST(self):
            if self.path == "/api/scan":
                self._handle_scan()
            else:
                self.send_error(404)

        def _serve_web_ui(self):
            """Serve the web UI landing page."""
            if not web_ui_content:
                self.send_error(404, "Web UI not found")
                return
            encoded = web_ui_content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _serve_latest_report(self):
            """Serve the latest HTML report at /report."""
            report = _find_latest_report(project_root)
            if report is None:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<h2>No report yet. Run a scan first.</h2>")
                return
            content = report.read_text(encoding="utf-8")
            encoded = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _handle_info(self):
            payload = json.dumps({"project_root": resolved_root})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))

        def _handle_browse(self):
            try:
                import tkinter as tk
                from tkinter import filedialog

                root = tk.Tk()
                root.withdraw()
                root.attributes("-topmost", True)
                folder = filedialog.askdirectory(
                    title="Select project folder to scan"
                )
                root.destroy()
            except Exception:
                folder = ""

            payload = json.dumps({"path": folder or ""})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))

        def _handle_rules(self):
            """Return all rule definitions as JSON."""
            if rules_cache["json"] is None:
                rules_cache["json"] = _rules_json()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(rules_cache["json"].encode("utf-8"))

        def _handle_scan(self):
            """Run a scan, save to history, and return JSON results."""
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                self._json_error(400, "Invalid JSON body")
                return

            target = payload.get("path", "").strip()
            profile = payload.get("profile", "saas")
            if not target:
                self._json_error(400, "Missing 'path' field")
                return
            if not os.path.isdir(target):
                self._json_error(400, f"Not a valid directory: {target}")
                return

            try:
                from shipsafe.service import ScanOptions, run_scan
                from shipsafe.reporters import json_reporter
                from shipsafe.history import save_scan, load_latest, diff_scans, score_trend
                from shipsafe.service import render_report

                options = ScanOptions(target=target, profile=profile)
                result = run_scan(options)

                # Save scan to history for new/resolved tracking
                save_scan(result, project_root=target)

                # Compute diff against previous scan
                scans = load_latest(target, count=2)
                diff_data = None
                if len(scans) >= 2:
                    diff_data = diff_scans(scans[1], scans[0])

                # Get trend data
                trend_data = score_trend(target)

                # Save HTML report too
                html_content = render_report(
                    result, "html",
                    trend_data=trend_data,
                    diff_data=diff_data,
                )
                save_report_html(html_content, project_root=target)

                # Return JSON with diff info
                response = json.loads(json_reporter.render(result))
                if diff_data:
                    response["diff"] = {
                        "new": list(diff_data.get("new", set())),
                        "resolved": list(diff_data.get("resolved", set())),
                    }
                if trend_data:
                    response["trend"] = trend_data
                response_text = json.dumps(response)
            except Exception as exc:
                self._json_error(500, str(exc))
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(response_text.encode("utf-8"))

        def _json_error(self, code, message):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": message}).encode("utf-8"))

    url = f"http://localhost:{port}/"
    print(f"ShipSafe running at {url}")
    print("Press Ctrl+C to stop.")

    # Ensure .shipsafe dir exists for static file serving
    Path(shipsafe_dir).mkdir(parents=True, exist_ok=True)

    server = _ThreadingHTTPServer(("127.0.0.1", port), Handler)

    if open_browser:
        def _open_browser():
            if sys.platform == "win32":
                import subprocess
                subprocess.Popen(
                    ["cmd", "/c", "start", "", url],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            else:
                webbrowser.open(url)
        threading.Timer(0.3, _open_browser).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


def save_report_html(html_content: str, project_root: str = ".") -> Path:
    """Save an HTML report to .shipsafe/latest-report.html.

    Returns the path to the saved file.
    """
    shipsafe_dir = Path(project_root).resolve() / ".shipsafe"
    shipsafe_dir.mkdir(parents=True, exist_ok=True)
    report_path = shipsafe_dir / "latest-report.html"
    report_path.write_text(html_content, encoding="utf-8")
    return report_path
