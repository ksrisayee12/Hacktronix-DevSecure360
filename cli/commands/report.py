"""
DevSecure360 CLI — Report Commands
=====================================
Commands: report, report json, report html, report pdf, export
"""

from __future__ import annotations
import os
import json
import csv
from datetime import datetime
from typing import Optional

import typer
from rich.text import Text

from cli.theme import (
    console, make_panel, make_success_panel, make_error_panel, make_warning_panel,
    severity_icon, PRIMARY_CYAN, SUCCESS_COLOR, WARNING_COLOR, CRITICAL_COLOR, SECONDARY,
    SEVERITY_COLORS,
)
from cli.utils.session import get_session
from cli.utils.engine_bridge import get_field, get_history
from cli.utils.formatter import findings_to_table, score_to_panel
from cli.utils.progress import report_progress
from cli.config import get_config

app = typer.Typer(help="Generate security reports")

# Report output directory (created if absent)
REPORTS_DIR = os.path.join(os.getcwd(), "cli", "reports")


def _ensure_reports_dir() -> str:
    cfg      = get_config()
    out_dir  = cfg.report_output_dir
    abs_dir  = os.path.abspath(out_dir)
    os.makedirs(abs_dir, exist_ok=True)
    return abs_dir


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ─────────────────────────────────────────────
# devsecure report  (terminal summary)
# ─────────────────────────────────────────────

@app.command("report")
def report(
    fmt: Optional[str] = typer.Argument(
        None, help="Output format: json | html | pdf | csv"
    ),
):
    """
    Generate a security report.

    \b
    Examples:
      devsecure report           → Print summary to terminal
      devsecure report json      → Save JSON report
      devsecure report html      → Save styled HTML report
      devsecure report pdf       → Save PDF report
    """
    if not isinstance(fmt, str):
        fmt = getattr(fmt, "default", None)
        if not isinstance(fmt, str):
            fmt = None

    if fmt:
        fmt = fmt.lower().strip()
        if fmt.startswith("report "):
            fmt = fmt.replace("report ", "", 1).strip()
        dispatch = {
            "json": report_json,
            "html": report_html,
            "pdf":  report_pdf,
            "csv":  export,
        }
        if fmt in dispatch:
            dispatch[fmt]()
            return
        else:
            console.print(make_error_panel(
                Text(f"\n  Unknown format '{fmt}'.\n  Valid: json | html | pdf | csv\n"),
            ))
            return

    # Terminal summary
    session = get_session()
    if not session.scan_ran or not session.findings:
        console.print(make_warning_panel(
            Text("\n  No scan results in session.\n  Run [cyan]devsecure scan .[/cyan] first.\n"),
            title="No Data",
        ))
        return

    findings = session.findings
    score    = session.score or {}

    console.print()
    console.print(score_to_panel(score, target=session.scan_target or ""))
    console.print()
    console.print(findings_to_table(findings, title="Security Report — All Findings"))
    console.print()

    content = Text()
    content.append("  Export options:\n\n", style=f"bold {PRIMARY_CYAN}")
    content.append("  [cyan]devsecure report json[/cyan]  → JSON report file\n")
    content.append("  [cyan]devsecure report html[/cyan]  → Styled HTML report\n")
    content.append("  [cyan]devsecure report pdf[/cyan]   → PDF report\n")
    content.append("  [cyan]devsecure export[/cyan]       → CSV export\n")
    console.print(make_panel(content, title="Export"))


# ─────────────────────────────────────────────
# devsecure report json
# ─────────────────────────────────────────────

@app.command("json")
def report_json():
    """Save a JSON security report."""
    session  = get_session()
    findings = session.findings or []
    score    = session.score    or {}

    report_data = _build_report_data(findings, score, session)

    out_dir  = _ensure_reports_dir()
    filename = f"devsecure_report_{_timestamp()}.json"
    filepath = os.path.join(out_dir, filename)

    with report_progress("json"):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)

    console.print(make_success_panel(
        Text(f"\n  JSON report saved:\n  {filepath}\n", style="white"),
        title="Report Exported",
    ))


# ─────────────────────────────────────────────
# devsecure report html
# ─────────────────────────────────────────────

@app.command("html")
def report_html():
    """Save a styled HTML security report."""
    session  = get_session()
    findings = session.findings or []
    score    = session.score    or {}

    out_dir  = _ensure_reports_dir()
    filename = f"devsecure_report_{_timestamp()}.html"
    filepath = os.path.join(out_dir, filename)

    with report_progress("html"):
        html = _build_html_report(findings, score, session)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

    console.print(make_success_panel(
        Text(f"\n  HTML report saved:\n  {filepath}\n\n  Open in a browser to view.\n", style="white"),
        title="Report Exported",
    ))


# ─────────────────────────────────────────────
# devsecure report pdf
# ─────────────────────────────────────────────

@app.command("pdf")
def report_pdf():
    """Save a PDF security report (requires weasyprint)."""
    try:
        import weasyprint  # type: ignore
    except ImportError:
        console.print(make_warning_panel(
            Text(
                "\n  weasyprint is not installed.\n"
                "  Falling back to HTML report.\n\n"
                "  To install: pip install weasyprint\n"
                "  (requires GTK/Cairo on Windows — see weasyprint docs)\n",
                style="white",
            ),
            title="PDF Unavailable",
        ))
        report_html()
        return

    session  = get_session()
    findings = session.findings or []
    score    = session.score    or {}

    out_dir  = _ensure_reports_dir()
    filename = f"devsecure_report_{_timestamp()}.pdf"
    filepath = os.path.join(out_dir, filename)

    with report_progress("pdf"):
        html = _build_html_report(findings, score, session)
        weasyprint.HTML(string=html).write_pdf(filepath)

    console.print(make_success_panel(
        Text(f"\n  PDF report saved:\n  {filepath}\n", style="white"),
        title="Report Exported",
    ))


# ─────────────────────────────────────────────
# devsecure export  (CSV)
# ─────────────────────────────────────────────

@app.command("export")
def export(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output CSV file path"),
):
    """Export findings as a CSV file."""
    session  = get_session()
    findings = session.findings or []

    if not findings:
        console.print(make_warning_panel(
            Text("\n  No findings to export.\n  Run [cyan]devsecure scan .[/cyan] first.\n"),
        ))
        return

    out_dir  = _ensure_reports_dir()
    filename = output or os.path.join(out_dir, f"devsecure_findings_{_timestamp()}.csv")
    filepath = os.path.abspath(filename)

    fields = ["id", "severity", "vuln_class", "file", "line", "issue", "cwe", "owasp",
              "confidence", "cvss_score", "description", "remediation", "tool"]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = {k: get_field(finding, k, "") for k in fields}
            writer.writerow(row)

    console.print(make_success_panel(
        Text(f"\n  CSV exported:\n  {filepath}\n  ({len(findings)} findings)\n", style="white"),
        title="Export Complete",
    ))


# ─────────────────────────────────────────────
# BUILDERS
# ─────────────────────────────────────────────

def _build_report_data(findings: list, score: dict, session) -> dict:
    from cli import __version__
    counts_by_severity = {}
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        counts_by_severity[sev] = sum(
            1 for f in findings if get_field(f, "severity", "") == sev
        )
    return {
        "generated_at":  datetime.utcnow().isoformat() + "Z",
        "cli_version":   __version__,
        "target":        session.scan_target or "",
        "score":         score,
        "summary": {
            "total_findings":    len(findings),
            "by_severity":       counts_by_severity,
        },
        "findings": [
            {k: get_field(f, k, None) for k in
             ["id", "rule_id", "vuln_class", "severity", "file", "line", "url",
              "issue", "description", "evidence", "cwe", "owasp", "cvss_score",
              "confidence", "remediation", "taint_trace", "tool"]}
            for f in findings
        ],
    }


def _build_html_report(findings: list, score: dict, session) -> str:
    """Build a self-contained styled HTML report."""
    from cli import __version__

    sev_colors = {
        "Critical": "#EF4444",
        "High":     "#F59E0B",
        "Medium":   "#06B6D4",
        "Low":      "#22C55E",
        "Info":     "#9CA3AF",
    }

    val   = score.get("score",    0)
    grade = score.get("grade",    "F")
    counts= score.get("counts",   {})
    cvss  = score.get("max_cvss", 0.0)

    target = session.scan_target or "N/A"
    ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = ""
    for i, f in enumerate(findings, 1):
        sev      = get_field(f, "severity",   "Info")
        color    = sev_colors.get(sev, "#9CA3AF")
        rows += f"""
        <tr>
          <td>{i}</td>
          <td><span class="badge" style="background:{color}">{sev}</span></td>
          <td>{get_field(f, 'vuln_class', '')}</td>
          <td>{os.path.basename(get_field(f, 'file', '') or '')}</td>
          <td>{get_field(f, 'line', '') or '—'}</td>
          <td>{get_field(f, 'issue', '')}</td>
          <td>{get_field(f, 'cwe', '') or '—'}</td>
          <td>{get_field(f, 'cvss_score', '') or '—'}</td>
        </tr>"""

    score_color = "#22C55E" if val >= 75 else ("#F59E0B" if val >= 50 else "#EF4444")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DevSecure360 Security Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }}
  .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
             padding: 2rem 3rem; border-bottom: 1px solid #2563EB; }}
  .logo {{ font-size: 1.6rem; font-weight: 800; color: #2563EB; letter-spacing: 2px; }}
  .subtitle {{ color: #06B6D4; margin-top: 0.25rem; font-size: 0.9rem; }}
  .meta {{ color: #9CA3AF; font-size: 0.85rem; margin-top: 0.5rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 3rem; }}
  .score-card {{ background: #1e293b; border: 1px solid {score_color}; border-radius: 12px;
                 padding: 1.5rem; display: inline-block; margin: 1rem 0 2rem; }}
  .score-val {{ font-size: 3rem; font-weight: 900; color: {score_color}; }}
  .score-grade {{ font-size: 1.2rem; color: {score_color}; margin-left: 0.5rem; }}
  .score-label {{ color: #9CA3AF; font-size: 0.85rem; }}
  .counts {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }}
  .count-item {{ background: #1e293b; border-radius: 8px; padding: 0.75rem 1.25rem;
                 text-align: center; border: 1px solid #334155; }}
  .count-n {{ font-size: 1.5rem; font-weight: 700; }}
  .count-label {{ font-size: 0.75rem; color: #9CA3AF; }}
  h2 {{ color: #06B6D4; font-size: 1.1rem; margin: 2rem 0 1rem;
        border-bottom: 1px solid #1e3a5f; padding-bottom: 0.5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ background: #1e3a5f; color: #06B6D4; padding: 0.75rem 1rem;
        text-align: left; font-weight: 600; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  tr:hover td {{ background: #1e293b; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
            font-size: 0.75rem; font-weight: 700; color: #fff; }}
  .footer {{ text-align: center; color: #475569; font-size: 0.8rem;
             padding: 2rem; border-top: 1px solid #1e293b; margin-top: 3rem; }}
</style>
</head>
<body>
<div class="header">
  <div class="logo">DEVSECURE360</div>
  <div class="subtitle">AI-Powered Application Security Report</div>
  <div class="meta">Generated: {ts}  ·  Target: {target}  ·  CLI v{__version__}</div>
</div>
<div class="container">
  <h2>Security Score</h2>
  <div class="score-card">
    <span class="score-val">{val}</span>
    <span class="score-grade">/ 100 — Grade {grade}</span>
    <div class="score-label">Max CVSS: {cvss:.1f}  ·  Total Findings: {len(findings)}</div>
  </div>
  <div class="counts">
    {"".join(
        '<div class="count-item"><div class="count-n" style="color:{c}">{n}</div><div class="count-label">{s}</div></div>'.format(
            c=sev_colors.get(sev, "#9CA3AF"), n=counts.get(sev, 0), s=sev
        )
        for sev in ["Critical", "High", "Medium", "Low", "Info"]
    )}
  </div>
  <h2>Findings ({len(findings)} total)</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Severity</th><th>Class</th><th>File</th>
          <th>Line</th><th>Issue</th><th>CWE</th><th>CVSS</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">DevSecure360 CLI v{__version__}  ·  AI-Powered Security</div>
</body>
</html>"""
