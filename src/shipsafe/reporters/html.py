"""Single-file HTML reporter with interactive dashboard.

Design system: "Machined Slate" - Space Grotesk headings, JetBrains Mono
for data, ember accent, chamfer-cut corners.  Dark mode primary.
All data embedded as JSON in a <script> tag.  Zero external JS libraries.
"""

import json
import os
from datetime import datetime, timezone
from html import escape

from shipsafe import __version__
from shipsafe.finding import Finding, ScanResult, Severity
from shipsafe.scoring import score_label

SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

SEVERITY_CLASS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


def _summary_counts(result: ScanResult) -> dict[str, int]:
    return result.to_dict()["summary"]


# ── OWASP URL helpers ────────────────────────────────────────────────────────

_OWASP_TOP10_URLS: dict[str, str] = {
    "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control.html",
    "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures.html",
    "A03:2021": "https://owasp.org/Top10/A03_2021-Injection.html",
    "A04:2021": "https://owasp.org/Top10/A04_2021-Insecure_Design.html",
    "A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration.html",
    "A06:2021": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components.html",
    "A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures.html",
    "A08:2021": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures.html",
    "A09:2021": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures.html",
    "A10:2021": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery.html",
}

_OWASP_LLM_BASE = "https://owasp.org/www-project-top-10-for-large-language-model/"


def _owasp_url(owasp_id: str) -> str:
    return _OWASP_TOP10_URLS.get(owasp_id, "")


def _owasp_llm_url(owasp_llm_id: str) -> str:
    return _OWASP_LLM_BASE if owasp_llm_id else ""


def _findings_json(result: ScanResult) -> str:
    """Serialize findings to JSON safe for embedding inside a <script> tag.

    Escapes ``</`` to ``<\\/`` so that a snippet containing ``</script>``
    cannot break out of the enclosing script block (standard HTML/JSON
    safety practice).
    """
    rows = []
    for f in result.findings:
        rows.append({
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "severity": f.severity.name,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "message": f.message,
            "fix": f.fix,
            "snippet": f.snippet,
            "fingerprint": f.fingerprint,
            "cwe_id": f.cwe_id or "",
            "confidence": f.confidence,
            "owasp_id": f.owasp_id or "",
            "owasp_url": _owasp_url(f.owasp_id or ""),
            "owasp_llm_id": getattr(f, "owasp_llm_id", None) or "",
            "owasp_llm_url": _owasp_llm_url(getattr(f, "owasp_llm_id", None) or ""),
            "guide_url": f.guide_url,
        })
    # Escape </  →  <\/  to prevent snippet content from closing the <script> tag.
    return json.dumps(rows).replace("</", "<\\/")


def _trend_json(trend_data: list[dict] | None) -> str:
    if not trend_data:
        return "[]"
    return json.dumps(trend_data)


def _diff_json(diff_data: dict | None) -> str:
    if not diff_data:
        return "null"
    return json.dumps({
        "new": list(diff_data.get("new", set())),
        "resolved": list(diff_data.get("resolved", set())),
        "persistent": list(diff_data.get("persistent", set())),
    })


def render(
    result: ScanResult,
    trend_data: list[dict] | None = None,
    diff_data: dict | None = None,
    suppressed_fps: set[str] | None = None,
) -> str:
    """Render a scan result as an interactive HTML dashboard."""
    label_key, label_text = score_label(result.score)
    score_class = label_key.lower()
    summary = _summary_counts(result)
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scanned_at_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Always show "ShipSafe" as the brand; target path is shown beneath
    project_name = "ShipSafe"

    new_count = len(diff_data.get("new", set())) if diff_data else 0
    resolved_count = len(diff_data.get("resolved", set())) if diff_data else 0
    suppressed_set = suppressed_fps or set()
    suppressed_count = sum(1 for f in result.findings if f.fingerprint in suppressed_set)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ShipSafe Security Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      color-scheme: dark light;
      --bg: #1A1D23;
      --surface: #21242B;
      --surface-raised: #282C34;
      --border: #2E333A;
      --border-focus: #3D4450;
      --text: #E8E9EB;
      --text-2: #8B8F96;
      --text-3: #565A62;
      --accent: #E07A3A;
      --accent-hover: #C96A2F;
      --accent-muted: rgba(224,122,58,0.12);
      --success: #2FB380;
      --success-muted: rgba(47,179,128,0.10);
      --critical: #D14343;
      --warning: #D4A72C;
      --info-blue: #4A90B8;
      --code-bg: #0B0D10;
      --font-head: 'Space Grotesk', system-ui, sans-serif;
      --font-body: 'Plus Jakarta Sans', system-ui, sans-serif;
      --font-mono: 'JetBrains Mono', 'Cascadia Code', monospace;
      --radius-card: 4px 4px 0px 4px;
      --radius-btn: 4px 4px 4px 0px;
      --radius-badge: 3px;
    }}
    [data-theme="light"] {{
      --bg: #F4F4F0;
      --surface: #FAFAF8;
      --surface-raised: #EEEEEA;
      --border: #E0E1DE;
      --border-focus: #C8C9C6;
      --text: #111110;
      --text-2: #6B6B69;
      --text-3: #A0A09E;
      --accent: #C96A2F;
      --accent-hover: #B05A25;
      --accent-muted: rgba(201,106,47,0.10);
      --success-muted: rgba(47,179,128,0.08);
      --code-bg: #1d1c19;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; transition: background-color 0.25s ease, color 0.25s ease, border-color 0.25s ease; }}
    body {{
      font-family: var(--font-body);
      color: var(--text);
      background: var(--bg);
      font-size: 13px;
      line-height: 1.55;
    }}
    .page {{ max-width: 1080px; margin: 0 auto; padding: 32px 24px 48px; }}
    .report-header {{
      position: sticky; top: 0; z-index: 100;
      background: var(--surface); border-bottom: 1px solid var(--border);
      padding: 10px 24px; display: flex; align-items: center; justify-content: space-between;
      color: var(--text-2);
    }}
    .report-header-title {{ display: flex; align-items: baseline; gap: 10px; }}
    .header-project {{ font-family: var(--font-head); font-size: 24px; font-weight: 700; color: var(--text); }}
    .header-subtitle {{ font-size: 13px; color: var(--text-2); }}
    .topbar {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 12px 0; margin-bottom: 24px;
      border-bottom: 1px solid var(--border);
    }}
    .topbar-left {{
      display: flex; align-items: center; gap: 8px;
      font-family: var(--font-mono); font-size: 13px; color: var(--text-2);
    }}
    .topbar-right {{ display: flex; align-items: center; gap: 12px; }}
    .theme-toggle {{
      background: none; border: 1px solid var(--border); color: var(--text-2);
      width: 32px; height: 32px; border-radius: var(--radius-badge); cursor: pointer;
      font-size: 14px; display: flex; align-items: center; justify-content: center;
    }}
    .theme-toggle:hover {{ border-color: var(--border-focus); color: var(--text); }}
    .status-row {{
      display: flex; align-items: flex-start; gap: 24px; margin-bottom: 24px;
      flex-wrap: wrap;
    }}
    .score-chip {{
      display: flex; flex-direction: column; align-items: flex-start;
      padding: 16px 20px; border-radius: var(--radius-card);
      min-width: 120px; color: #fff;
    }}
    .score-chip.green {{ background: #276749; }}
    .score-chip.yellow {{ background: #975a16; }}
    .score-chip.orange {{ background: #c05621; }}
    .score-chip.red {{ background: #9b2c2c; }}
    .score-label {{
      font-family: var(--font-head); font-size: 11px; font-weight: 500;
      text-transform: uppercase; letter-spacing: 0.12em; opacity: 0.8;
      margin-bottom: 4px;
    }}
    .score-value {{
      font-family: var(--font-head); font-size: 32px; font-weight: 700; line-height: 1;
    }}
    .score-status {{ font-size: 13px; margin-top: 6px; font-weight: 500; opacity: 1; }}
    .status-meta {{
      display: flex; flex-direction: column; gap: 8px; color: var(--text-2); font-size: 13px;
    }}
    .status-meta strong {{ color: var(--text); }}
    .diff-badges {{ display: flex; gap: 8px; margin-top: 4px; }}
    .badge {{
      display: inline-flex; align-items: center; gap: 4px;
      padding: 2px 8px; border-radius: var(--radius-badge);
      font-size: 12px; font-weight: 600;
    }}
    .badge-new {{ background: var(--accent-muted); color: var(--accent); }}
    .badge-resolved {{ background: var(--success-muted); color: var(--success); }}
    .badge-suppressed {{ background: rgba(74,144,184,0.12); color: var(--info-blue); }}
    .trend-section {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius-card); padding: 16px; margin-bottom: 24px;
    }}
    .trend-section svg {{ width: 100%; height: 100px; }}
    .trend-caption {{ font-size: 15px; font-weight: 500; color: var(--text-2); margin-top: 10px; font-family: var(--font-body); }}
    .summary-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 12px; margin-bottom: 24px;
    }}
    .stat-card {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius-card); padding: 12px 16px;
    }}
    .stat-card-label {{
      font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
      color: var(--text-3); margin-bottom: 4px;
    }}
    .stat-card-value {{ font-family: var(--font-head); font-size: 24px; font-weight: 700; }}
    .sev-critical {{ color: var(--critical); }}
    .sev-high {{ color: var(--warning); }}
    .sev-medium {{ color: #D97706; }}
    .sev-low {{ color: #0f766e; }}
    .sev-info {{ color: var(--text-3); }}
    .tab-nav {{
      display: flex; gap: 24px; border-bottom: 1px solid var(--border);
      margin-bottom: 16px;
    }}
    .tab-btn {{
      background: none; border: none; color: var(--text-2); font-size: 13px;
      font-family: var(--font-body); font-weight: 500; padding: 8px 0;
      cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -1px;
    }}
    .tab-btn:hover {{ color: var(--text); }}
    .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
    .filter-bar {{
      display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px;
      align-items: center;
    }}
    .filter-bar select, .filter-bar input {{
      background: var(--surface); border: 1px solid var(--border);
      color: var(--text); font-family: var(--font-mono); font-size: 12px;
      padding: 4px 8px; border-radius: var(--radius-badge); height: 28px;
    }}
    .filter-bar select:focus, .filter-bar input:focus {{
      outline: none; border-color: var(--accent);
    }}
    .findings-table {{
      width: 100%; border-collapse: collapse; font-size: 13px;
    }}
    .findings-table th {{
      text-align: left; padding: 8px 10px; font-size: 11px;
      text-transform: uppercase; letter-spacing: 0.06em;
      color: var(--text-3); border-bottom: 1px solid var(--border);
      cursor: pointer; user-select: none;
    }}
    .findings-table th:hover {{ color: var(--text-2); }}
    .findings-table td {{
      padding: 8px 10px; border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    .findings-table tr {{ height: 36px; }}
    .findings-table tr:hover {{ background: var(--surface-raised); }}
    .findings-table tr.expanded {{ background: var(--surface); }}
    .findings-table tr.new-finding td:first-child {{
      box-shadow: inset 3px 0 0 var(--accent);
    }}
    .findings-table tr.resolved-finding td:first-child {{
      box-shadow: inset 3px 0 0 var(--success);
    }}
    .findings-table tr.suppressed-finding {{ opacity: 0.6; }}
    .sev-dot {{
      display: inline-block; width: 8px; height: 8px; border-radius: 50%;
      margin-right: 6px; vertical-align: middle;
    }}
    .sev-dot.critical {{ background: var(--critical); }}
    .sev-dot.high {{ background: var(--warning); }}
    .sev-dot.medium {{ background: #D97706; }}
    .sev-dot.low {{ background: #0f766e; }}
    .sev-dot.info {{ background: var(--text-3); }}
    .fp-short {{ font-family: var(--font-mono); font-size: 11px; color: var(--text-3); }}
    .file-ref {{ font-family: var(--font-mono); font-size: 12px; }}
    .confidence-badge {{
      font-size: 10px; padding: 1px 5px; border-radius: 2px;
      text-transform: uppercase; letter-spacing: 0.04em;
      border: 1px solid var(--border);
    }}
    .confidence-high {{ color: var(--success); border-color: var(--success); }}
    .confidence-medium {{ color: var(--warning); border-color: var(--warning); }}
    .confidence-low {{ color: var(--critical); border-color: var(--critical); }}
    .detail-row {{ display: none; }}
    .detail-row.visible {{ display: table-row; }}
    .detail-cell {{
      padding: 16px 20px; background: var(--surface-raised);
      border-bottom: 1px solid var(--border);
    }}
    .detail-grid {{
      display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
    }}
    .detail-section h4 {{
      font-family: var(--font-head); font-size: 13px; font-weight: 600;
      color: var(--text-2); margin-bottom: 8px;
      text-transform: uppercase; letter-spacing: 0.06em;
    }}
    .detail-section p {{ white-space: pre-wrap; line-height: 1.6; }}
    .detail-code {{
      font-family: var(--font-mono); font-size: 12px; line-height: 1.5;
      background: var(--code-bg); color: #fef7eb; padding: 12px 16px;
      border-radius: var(--radius-badge); overflow-x: auto;
      white-space: pre-wrap; word-break: break-all;
    }}
    .detail-meta {{
      display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 12px;
      font-size: 12px; color: var(--text-2);
    }}
    .detail-meta dl {{ display: flex; flex-direction: column; gap: 2px; }}
    .detail-meta dt {{ font-size: 10px; text-transform: uppercase; color: var(--text-3); }}
    .detail-meta dd {{ font-family: var(--font-mono); margin: 0; }}
    .detail-meta a {{ color: var(--accent); text-decoration: none; }}
    .detail-meta a:hover {{ text-decoration: underline; }}
    .copy-fix-btn {{
      display: inline-flex; align-items: center; gap: 6px;
      padding: 8px 16px; background: var(--accent); color: #fff;
      border: none; border-radius: var(--radius-btn); cursor: pointer;
      font-size: 13px; font-weight: 500; font-family: var(--font-body);
      transition: background 0.15s; margin-top: 12px;
    }}
    .copy-fix-btn:hover {{ background: var(--accent-hover); }}
    .copy-fix-btn.copied {{ background: var(--success); }}
    .copy-fix-btn svg {{ width: 14px; height: 14px; }}
    .breakdown {{ margin-bottom: 24px; }}
    .breakdown table {{ width: 100%; border-collapse: collapse; }}
    .breakdown th, .breakdown td {{
      padding: 8px 10px; text-align: left; font-size: 13px;
      border-bottom: 1px solid var(--border);
    }}
    .breakdown th {{
      font-size: 11px; text-transform: uppercase; color: var(--text-3);
      letter-spacing: 0.06em;
    }}
    .empty-state {{
      text-align: center; padding: 48px 24px;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius-card);
    }}
    .empty-state .check {{ font-size: 48px; color: var(--success); margin-bottom: 8px; }}
    .empty-state h2 {{ font-family: var(--font-head); font-size: 18px; margin-bottom: 8px; }}
    .footer {{
      margin-top: 40px; padding: 20px 0; border-top: 1px solid var(--border);
      font-size: 13px; color: var(--text-3); text-align: center;
      line-height: 1.7;
    }}
    .footer-line2 {{ font-size: 11px; margin-top: 4px; color: var(--text-3); opacity: 0.8; }}
    .print-btn {{
      background: none; border: 1px solid var(--border); color: var(--text-2);
      padding: 4px 12px; border-radius: var(--radius-badge); cursor: pointer;
      font-size: 12px;
    }}
    .print-btn:hover {{ border-color: var(--border-focus); color: var(--text); }}
    .help-icon {{
      display: inline-flex; align-items: center; justify-content: center;
      width: 18px; height: 18px; border-radius: 50%; border: 1.5px solid var(--accent);
      color: var(--accent); font-size: 11px; font-weight: 700; cursor: pointer;
      vertical-align: middle; margin-left: 6px; position: relative;
      font-family: var(--font-body); line-height: 1; user-select: none;
      opacity: 0.85;
    }}
    .help-icon:hover {{ opacity: 1; background: var(--accent-muted); }}
    .help-popover {{
      display: none; position: absolute; top: calc(100% + 8px); left: -8px; z-index: 200;
      background: var(--surface); border: 1px solid var(--border-focus);
      border-radius: var(--radius-badge); padding: 14px 16px;
      font-size: 13px; font-weight: 400; color: var(--text);
      line-height: 1.65; width: 320px; text-transform: none; letter-spacing: 0;
      box-shadow: 0 6px 24px rgba(0,0,0,0.35);
    }}
    .help-popover strong {{ color: var(--accent); }}
    .help-icon.active .help-popover {{ display: block; }}
    @media print {{
      body {{ background: white !important; color: #111 !important; }}
      .topbar, .filter-bar, .tab-nav, .theme-toggle, .print-btn, .report-header {{ display: none !important; }}
      .score-chip {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      .sev-dot {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      .page {{ max-width: 100%; padding: 0; }}
    }}
    @media (max-width: 640px) {{
      .page {{ padding: 16px 12px; }}
      .status-row {{ flex-direction: column; }}
      .detail-grid {{ grid-template-columns: 1fr; }}
      .summary-grid {{ grid-template-columns: repeat(3, 1fr); }}
    }}
  </style>
</head>
<body>
  <header class="report-header">
    <div class="report-header-title">
      <span class="header-project">{escape(project_name)}</span>
      <span class="header-subtitle">Security Report</span>
    </div>
    <time class="local-time" datetime="{scanned_at_iso}">{scanned_at}</time>
  </header>
  <main class="page">
    <div class="topbar">
      <div class="topbar-left">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 2h10v12H3z" stroke="currentColor" stroke-width="1.5"/><path d="M6 5h4M6 8h4" stroke="currentColor" stroke-width="1"/></svg>
        <span>{escape(result.target)}</span>
      </div>
      <div class="topbar-right">
        <button class="print-btn" onclick="downloadJSON()">Download JSON</button>
        <button class="print-btn" onclick="window.location.href='/'" title="Back to scanner"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg> New Scan</button>
        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme" aria-label="Toggle theme">&#9681;</button>
      </div>
    </div>

    <section class="status-row">
      <div class="score-chip {score_class}">
        <span class="score-label">Security Score <span class="help-icon" onclick="event.stopPropagation();this.classList.toggle('active')">?<span class="help-popover"><strong>100</strong> = no findings.<br><br>Points deducted per severity:<br>&bull; <strong>CRITICAL</strong> &minus;25 (cap &minus;75)<br>&bull; <strong>HIGH</strong> &minus;10 (cap &minus;40)<br>&bull; <strong>MEDIUM</strong> &minus;5 (cap &minus;25)<br>&bull; <strong>LOW</strong> &minus;2 (cap &minus;10)<br><br>See Score Breakdown tab for full details.</span></span></span>
        <span class="score-value">{result.score}<small style="font-size:16px;opacity:0.7">/100</small></span>
        <span class="score-status">{escape(label_text)}</span>
      </div>
      <div class="status-meta">
        <span><strong>Files scanned:</strong> {result.files_scanned}</span>
        <span><strong>Scanned:</strong> <time class="local-time" datetime="{scanned_at_iso}">{scanned_at}</time></span>
        <span><strong>ShipSafe:</strong> v{escape(__version__)}</span>
        <div class="diff-badges">
          {f'<span class="badge badge-new">{new_count} New</span>' if new_count else ''}
          {f'<span class="badge badge-resolved">{resolved_count} Resolved</span>' if resolved_count else ''}
          {f'<span class="badge badge-suppressed">{suppressed_count} Suppressed</span>' if suppressed_count else ''}
        </div>
      </div>
    </section>

    <div id="trend-container" class="trend-section" style="display:none">
      <svg id="trend-svg" viewBox="0 0 800 100" preserveAspectRatio="none"></svg>
      <div class="trend-caption" id="trend-caption"></div>
    </div>

    <section class="summary-grid">
      <div class="stat-card">
        <div class="stat-card-label">Total</div>
        <div class="stat-card-value">{summary["total"]}</div>
      </div>
      <div class="stat-card">
        <div class="stat-card-label">Critical</div>
        <div class="stat-card-value sev-critical">{summary["critical"]}</div>
      </div>
      <div class="stat-card">
        <div class="stat-card-label">High</div>
        <div class="stat-card-value sev-high">{summary["high"]}</div>
      </div>
      <div class="stat-card">
        <div class="stat-card-label">Medium</div>
        <div class="stat-card-value sev-medium">{summary["medium"]}</div>
      </div>
      <div class="stat-card">
        <div class="stat-card-label">Low</div>
        <div class="stat-card-value sev-low">{summary["low"]}</div>
      </div>
      <div class="stat-card">
        <div class="stat-card-label">Info</div>
        <div class="stat-card-value sev-info">{summary["info"]}</div>
      </div>
    </section>

    <nav class="tab-nav" id="tab-nav">
      <button class="tab-btn active" data-tab="all">All Findings</button>
      <button class="tab-btn" data-tab="new">New</button>
      <button class="tab-btn" data-tab="resolved">Resolved</button>
      <button class="tab-btn" data-tab="breakdown">Score Breakdown</button>
    </nav>

    <div class="filter-bar" id="filter-bar">
      <select id="filter-severity">
        <option value="">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
        <option value="INFO">Info</option>
      </select>
      <select id="filter-confidence">
        <option value="">All Confidence</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <input id="filter-search" type="text" placeholder="Search rule, file, or text..." style="min-width:200px">
    </div>

    <div id="tab-all">
      <table class="findings-table" id="findings-table">
        <thead>
          <tr>
            <th data-sort="severity">Severity</th>
            <th data-sort="fingerprint">ID</th>
            <th data-sort="file_path">File</th>
            <th data-sort="rule_id">Rule</th>
            <th data-sort="confidence">Confidence <span class="help-icon" onclick="event.stopPropagation();this.classList.toggle('active')">?<span class="help-popover"><strong>HIGH</strong> = almost certainly a real issue.<br><br><strong>MEDIUM</strong> = likely real, worth investigating.<br><br><strong>LOW</strong> = may be a false positive - verify manually.</span></span></th>
            <th data-sort="status">Status</th>
          </tr>
        </thead>
        <tbody id="findings-body"></tbody>
      </table>
    </div>

    <div id="tab-new" style="display:none">
      <table class="findings-table" id="new-table">
        <thead>
          <tr><th>Severity</th><th>ID</th><th>File</th><th>Rule</th><th>Confidence</th></tr>
        </thead>
        <tbody id="new-body"></tbody>
      </table>
    </div>

    <div id="tab-resolved" style="display:none">
      <p style="color:var(--text-2);font-size:13px" id="resolved-info"></p>
    </div>

    <div id="tab-breakdown" style="display:none" class="breakdown">
      <table>
        <thead>
          <tr><th>Severity</th><th>Count</th><th>Penalty / finding</th><th>Points deducted</th><th>Cap</th></tr>
        </thead>
        <tbody id="breakdown-body"></tbody>
      </table>
    </div>

    <div class="empty-state" id="empty-state" style="display:none">
      <div class="check success-icon">&#10003;</div>
      <h2>Clean scan - no findings</h2>
      <p style="color:var(--text-2)">{result.files_scanned} files scanned. Zero security issues detected.<br><br>Looks clean. Ship with caution.<br><span style="color:var(--text-3);font-size:12px">ShipSafe was built with AI assistance and curated by a human.</span></p>
    </div>

    <footer class="footer">
      ShipSafe v{escape(__version__)} &middot; <time class="local-time" datetime="{scanned_at_iso}">{scanned_at}</time> &middot;
      Deterministic regex scan. Your code never left this machine.
      <div class="footer-line2">Detects known vulnerability patterns only. Does not detect runtime-only issues, business logic flaws, or semantic vulnerabilities.</div>
    </footer>
  </main>

  <script>
  const FINDINGS = {_findings_json(result)};
  const TREND = {_trend_json(trend_data)};
  const DIFF = {_diff_json(diff_data)};
  const BREAKDOWN = {json.dumps(result.score_breakdown)};
  const SUPPRESSED = {json.dumps(list(suppressed_set))};
  const SEV_ORDER = {{"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}};

  function downloadJSON() {{
    const blob = new Blob([JSON.stringify(FINDINGS, null, 2)], {{type: 'application/json'}});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'shipsafe-report.json';
    a.click();
    URL.revokeObjectURL(url);
  }}
  function toggleTheme() {{
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    html.setAttribute('data-theme', current === 'light' ? 'dark' : 'light');
  }}
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {{
    document.documentElement.setAttribute('data-theme', 'light');
  }}

  // Convert UTC timestamps to local time
  document.querySelectorAll('.local-time').forEach(el => {{
    try {{
      const utc = el.getAttribute('datetime');
      const d = new Date(utc);
      if (isNaN(d.getTime())) return;
      const local = d.toLocaleString(undefined, {{
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit'
      }});
      const offset = -d.getTimezoneOffset();
      const sign = offset >= 0 ? '+' : '-';
      const hrs = Math.abs(Math.floor(offset / 60));
      const mins = Math.abs(offset % 60);
      const tz = 'UTC' + sign + hrs + (mins ? ':' + String(mins).padStart(2, '0') : '');
      el.textContent = local + ' (' + tz + ')';
    }} catch(e) {{}}
  }});

  document.querySelectorAll('.tab-btn').forEach(btn => {{
    btn.addEventListener('click', () => {{
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.dataset.tab;
      ['all','new','resolved','breakdown'].forEach(t => {{
        const el = document.getElementById('tab-' + t);
        if (el) el.style.display = t === tab ? '' : 'none';
      }});
      document.getElementById('filter-bar').style.display = (tab === 'all' || tab === 'new') ? '' : 'none';
    }});
  }});

  if (TREND.length > 1) {{
    const container = document.getElementById('trend-container');
    container.style.display = '';
    const svg = document.getElementById('trend-svg');
    const scores = TREND.map(t => t.score);
    const minScore = Math.min(...scores), maxScore = Math.max(...scores);
    if (minScore === maxScore) {{
      // Flat trend - replace sparkline with stable message
      svg.style.display = 'none';
      document.getElementById('trend-caption').textContent =
        `\u2192 Score stable at ${{minScore}}/100 across ${{TREND.length}} scans.`;
    }} else {{
      const w = 800, h = 100, pad = 4;
      const minS = Math.max(0, minScore - 5);
      const maxS = Math.min(100, maxScore + 5);
      const range = maxS - minS || 1;
      const points = TREND.map((t, i) => {{
        const x = pad + (i / (TREND.length - 1)) * (w - 2*pad);
        const y = h - pad - ((t.score - minS) / range) * (h - 2*pad);
        return `${{x}},${{y}}`;
      }});
      const fillPoints = points.join(' ') + ` ${{w-pad}},${{h-pad}} ${{pad}},${{h-pad}}`;
      svg.innerHTML = `<polygon points="${{fillPoints}}" fill="var(--accent-muted)" />`
        + `<polyline points="${{points.join(' ')}}" fill="none" stroke="var(--accent)" stroke-width="2" />`
        + `<text x="${{pad}}" y="12" fill="var(--text-3)" font-size="11" font-family="var(--font-mono)">${{maxScore}}</text>`
        + `<text x="${{pad}}" y="${{h - 2}}" fill="var(--text-3)" font-size="11" font-family="var(--font-mono)">${{minScore}}</text>`;
      TREND.forEach((t, i) => {{
        const x = pad + (i / (TREND.length - 1)) * (w - 2*pad);
        const y = h - pad - ((t.score - minS) / range) * (h - 2*pad);
        svg.innerHTML += `<circle cx="${{x}}" cy="${{y}}" r="3" fill="var(--accent)" />`;
      }});
      const first = scores[0], last = scores[scores.length - 1];
      const arrow = last > first ? '\u2191' : last < first ? '\u2193' : '\u2192';
      document.getElementById('trend-caption').textContent =
        `${{arrow}} Based on ${{TREND.length}} scans. Score range: ${{minScore}}-${{maxScore}}`;
    }}
  }}

  const newFps = DIFF ? new Set(DIFF.new) : new Set();
  const resolvedFps = DIFF ? new Set(DIFF.resolved) : new Set();
  const suppressedSet = new Set(SUPPRESSED);

  function escHtml(s) {{ const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }}

  function statusOf(f) {{
    if (suppressedSet.has(f.fingerprint)) return 'suppressed';
    if (newFps.has(f.fingerprint)) return 'new';
    return 'existing';
  }}

  function renderRow(f) {{
    const sev = f.severity.toLowerCase();
    const status = statusOf(f);
    const cls = status === 'new' ? 'new-finding' : status === 'suppressed' ? 'suppressed-finding' : '';
    const statusBadge = status === 'new' ? '<span class="badge badge-new">New</span>'
      : status === 'suppressed' ? '<span class="badge badge-suppressed">Suppressed</span>'
      : '';
    const confCls = 'confidence-' + f.confidence;
    return `<tr class="${{cls}}" data-fp="${{f.fingerprint}}" data-sev="${{f.severity}}" data-conf="${{f.confidence}}" onclick="toggleDetail(this)">
      <td><span class="sev-dot ${{sev}}"></span>${{f.severity}}</td>
      <td class="fp-short">${{f.fingerprint.slice(0,10)}}</td>
      <td class="file-ref">${{escHtml(f.file_path)}}:${{f.line_number}}</td>
      <td>${{escHtml(f.rule_id)}}</td>
      <td><span class="confidence-badge ${{confCls}}">${{f.confidence}}</span></td>
      <td>${{statusBadge}}</td>
    </tr>
    <tr class="detail-row" id="detail-${{f.fingerprint}}">
      <td colspan="6" class="detail-cell">
        <div class="detail-meta">
          <dl><dt>Rule</dt><dd>${{escHtml(f.rule_id)}} - ${{escHtml(f.rule_name)}}</dd></dl>
          ${{f.cwe_id ? '<dl><dt>CWE</dt><dd>'+escHtml(f.cwe_id)+'</dd></dl>' : ''}}
          ${{f.owasp_id ? '<dl><dt>OWASP</dt><dd>'+(f.owasp_url?'<a href="'+escHtml(f.owasp_url)+'" target="_blank" rel="noopener">'+escHtml(f.owasp_id)+'</a>':escHtml(f.owasp_id))+'</dd></dl>' : ''}}
          ${{f.owasp_llm_id ? '<dl><dt>OWASP LLM</dt><dd>'+(f.owasp_llm_url?'<a href="'+escHtml(f.owasp_llm_url)+'" target="_blank" rel="noopener">'+escHtml(f.owasp_llm_id)+'</a>':escHtml(f.owasp_llm_id))+'</dd></dl>' : ''}}
          <dl><dt>Fingerprint</dt><dd style="font-size:11px">${{f.fingerprint}}</dd></dl>
        </div>
        <div class="detail-grid">
          <div class="detail-section"><h4>Why this matters</h4><p>${{escHtml(f.message)}}</p></div>
          <div class="detail-section"><h4>Fix</h4><p class="pre-text">${{escHtml(f.fix).replace(/\\n/g,'<br>')}}</p></div>
        </div>
        <div class="detail-section" style="margin-top:12px"><h4>Code</h4><pre class="detail-code">${{escHtml(f.snippet)}}</pre></div>
        <button class="copy-fix-btn" onclick="event.stopPropagation(); copyFixPrompt(this, '${{f.fingerprint}}')" title="Copy a ready-made fix prompt for your AI coding tool">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
          </svg>
          Copy fix prompt
        </button>
      </td>
    </tr>`;
  }}

  function copyFixPrompt(btn, fp) {{
    const f = FINDINGS.find(x => x.fingerprint === fp);
    if (!f) return;
    const prompt = 'Fix this security vulnerability in my code:\\n\\n'
      + 'Issue: ' + (f.rule_name || f.rule_id) + '\\n'
      + 'File: ' + f.file_path + '\\n'
      + 'Line: ' + f.line_number + '\\n'
      + 'Severity: ' + f.severity + '\\n\\n'
      + (f.fix || f.message) + '\\n\\n'
      + 'Please fix this specific issue without changing unrelated code.';
    navigator.clipboard.writeText(prompt).then(() => {{
      btn.classList.add('copied');
      btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg> Copied!';
      setTimeout(() => {{
        btn.classList.remove('copied');
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg> Copy fix prompt';
      }}, 2000);
    }});
  }}

  function renderTable() {{
    const sev = document.getElementById('filter-severity').value;
    const conf = document.getElementById('filter-confidence').value;
    const search = document.getElementById('filter-search').value.toLowerCase();
    let filtered = FINDINGS.filter(f => {{
      if (sev && f.severity !== sev) return false;
      if (conf && f.confidence !== conf) return false;
      if (search) {{
        const hay = (f.rule_id + f.rule_name + f.file_path + f.message + f.snippet).toLowerCase();
        if (!hay.includes(search)) return false;
      }}
      return true;
    }});
    document.getElementById('findings-body').innerHTML = filtered.map(renderRow).join('');
    const newFindings = FINDINGS.filter(f => newFps.has(f.fingerprint));
    document.getElementById('new-body').innerHTML = newFindings.map(renderRow).join('');
    document.getElementById('empty-state').style.display = FINDINGS.length === 0 ? '' : 'none';
    if (FINDINGS.length === 0) {{
      document.getElementById('tab-all').style.display = 'none';
      document.getElementById('filter-bar').style.display = 'none';
      document.getElementById('tab-nav').style.display = 'none';
    }}
  }}

  function toggleDetail(tr) {{
    const fp = tr.dataset.fp;
    if (!fp) return;
    const detail = document.getElementById('detail-' + fp);
    if (detail) {{
      detail.classList.toggle('visible');
      tr.classList.toggle('expanded');
    }}
  }}

  document.getElementById('filter-severity').addEventListener('change', renderTable);
  document.getElementById('filter-confidence').addEventListener('change', renderTable);
  document.getElementById('filter-search').addEventListener('input', renderTable);

  let sortCol = 'severity', sortAsc = true;
  document.querySelectorAll('#findings-table th[data-sort]').forEach(th => {{
    th.addEventListener('click', () => {{
      const col = th.dataset.sort;
      if (sortCol === col) sortAsc = !sortAsc; else {{ sortCol = col; sortAsc = true; }}
      FINDINGS.sort((a,b) => {{
        let va = a[col] || '', vb = b[col] || '';
        if (col === 'severity') {{ va = SEV_ORDER[a.severity]||9; vb = SEV_ORDER[b.severity]||9; }}
        if (va < vb) return sortAsc ? -1 : 1;
        if (va > vb) return sortAsc ? 1 : -1;
        return 0;
      }});
      renderTable();
    }});
  }});

  const sevNames = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  document.getElementById('breakdown-body').innerHTML = sevNames.map(s => {{
    const b = BREAKDOWN[s] || {{}};
    return `<tr><th>${{s}}</th><td>${{b.count||0}}</td><td>-${{b.weight||0}}</td><td>-${{b.applied_deduction||0}}</td><td>-${{b.cap||0}}</td></tr>`;
  }}).join('');

  if (DIFF && DIFF.resolved.length > 0) {{
    document.getElementById('resolved-info').innerHTML =
      `<strong>${{DIFF.resolved.length}}</strong> findings from the previous scan are no longer present:<br>`
      + DIFF.resolved.map(fp => `<span class="fp-short" style="margin:2px 4px;display:inline-block">${{fp.slice(0,12)}}</span>`).join('');
  }} else {{
    document.getElementById('resolved-info').textContent = 'No resolved findings (or no previous scan to compare against).';
  }}

  // Default sort: severity (CRITICAL first), then file path
  FINDINGS.sort((a,b) => {{
    const s = (SEV_ORDER[a.severity]||9) - (SEV_ORDER[b.severity]||9);
    if (s !== 0) return s;
    return (a.file_path||'').localeCompare(b.file_path||'');
  }});
  renderTable();

  // Close help popovers on outside click
  document.addEventListener('click', (e) => {{
    if (!e.target.closest('.help-icon')) {{
      document.querySelectorAll('.help-icon.active').forEach(h => h.classList.remove('active'));
    }}
  }});
  </script>
</body>
</html>
"""
