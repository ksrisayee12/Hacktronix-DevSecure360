"""
DevSecure360 CLI — Explain Commands
======================================
Commands: explain, explain <id>, explain critical/high/medium/low

Severity filter names match the Severity enum in shared/types.py exactly:
    Critical | High | Medium | Low | Info
"""

from __future__ import annotations
from typing import Optional

import typer
from rich.text import Text
from rich.rule import Rule
from rich.syntax import Syntax

from cli.theme import (
    console, make_panel, make_error_panel, make_warning_panel,
    severity_icon, severity_badge, PRIMARY_CYAN, SECONDARY, SEVERITY_COLORS,
)
from cli.utils.session import get_session
from cli.utils.formatter import (
    findings_to_table, finding_to_panel, taint_trace_tree, findings_summary_text,
)
from cli.utils.engine_bridge import get_field

app = typer.Typer(help="Explain and analyze findings from the last scan")

# Valid severity names matching the existing Severity enum
SEVERITY_LEVELS = {"critical", "high", "medium", "low", "info"}


# ─────────────────────────────────────────────
# devsecure explain
# ─────────────────────────────────────────────

@app.command("explain")
def explain(
    target: Optional[str] = typer.Argument(
        None,
        help="Finding ID, index, or severity level (critical/high/medium/low/info)",
    ),
    page: int = typer.Option(1, "--page", "-p", help="Page number for large lists"),
):
    """
    Explain findings from the last scan.

    \b
    Examples:
      devsecure explain               → Show all findings table
      devsecure explain 1             → Detail view for finding #1
      devsecure explain critical      → Show only Critical findings
      devsecure explain high          → Show only High findings
    """
    session = get_session()

    if not session.scan_ran or not session.findings:
        console.print(make_warning_panel(
            Text("\n  No scan results in session.\n  Run [cyan]devsecure scan .[/cyan] first.\n"),
            title="No Findings",
        ))
        return

    # Route based on argument
    if target is None:
        _show_all_findings(session.findings, page)
    elif target.lower() in SEVERITY_LEVELS:
        _show_by_severity(session.findings, target.capitalize())
    else:
        _show_single_finding(session.findings, target)


# ─────────────────────────────────────────────
# Show all findings — paginated table
# ─────────────────────────────────────────────

def _show_all_findings(findings: list, page: int = 1):
    PAGE_SIZE = 25
    total     = len(findings)
    start     = (page - 1) * PAGE_SIZE
    end       = start + PAGE_SIZE
    page_findings = findings[start:end]

    console.print()
    console.print(make_panel(
        findings_summary_text(findings),
        title=f"Findings  ·  {total} total",
    ))
    console.print()
    console.print(findings_to_table(
        page_findings,
        title=f"Findings  (page {page} of {max(1, -(-total // PAGE_SIZE))})",
    ))

    if end < total:
        console.print(f"\n  [dim]Use [cyan]--page {page + 1}[/cyan] to see more findings.[/dim]")
    console.print()


# ─────────────────────────────────────────────
# Show findings filtered by severity
# ─────────────────────────────────────────────

def _show_by_severity(findings: list, severity: str):
    """severity must be a capitalized Severity enum value: Critical, High, Medium, Low, Info"""
    filtered = [
        f for f in findings
        if get_field(f, "severity", "Info") == severity
    ]

    color = SEVERITY_COLORS.get(severity, SECONDARY)

    if not filtered:
        console.print(make_panel(
            Text(f"\n  No {severity} findings in the last scan.\n", style="white"),
            title=f"{severity_icon(severity)}  {severity} Findings",
            border_color=color,
        ))
        return

    console.print()
    console.print(findings_to_table(
        filtered,
        title=f"{severity_icon(severity)}  {severity} Findings  ({len(filtered)} total)",
    ))
    console.print()
    console.print(f"  [dim]Run [cyan]devsecure explain <number>[/cyan] for full details.[/dim]\n")


# ─────────────────────────────────────────────
# Show a single finding detail
# ─────────────────────────────────────────────

def _show_single_finding(findings: list, identifier: str):
    session = get_session()
    finding = session.get_finding_by_id(identifier)

    if finding is None:
        console.print(make_error_panel(
            Text(
                f"\n  Finding '{identifier}' not found.\n"
                f"  Use a number (1-{len(findings)}) or a finding UUID.\n",
                style="white",
            ),
        ))
        return

    # Try to determine index for display
    idx = None
    if identifier.isdigit():
        idx = int(identifier)
    else:
        for i, f in enumerate(findings, 1):
            fid = get_field(f, "id", "")
            if fid and fid.startswith(identifier):
                idx = i
                break

    console.print()
    console.print(finding_to_panel(finding, index=idx or 0))

    # Evidence block (syntax highlighted)
    evidence = get_field(finding, "evidence", None)
    if evidence and evidence.strip():
        file_path = get_field(finding, "file", "") or ""
        ext = file_path.rsplit(".", 1)[-1].lower() if file_path else "python"
        lang_map = {
            "py": "python", "js": "javascript", "ts": "typescript",
            "java": "java", "php": "php", "c": "c", "cpp": "cpp",
            "go": "go", "cs": "csharp",
        }
        lang = lang_map.get(ext, "python")
        console.print()
        console.print(make_panel(
            Syntax(evidence, lang, theme="monokai", line_numbers=True, word_wrap=True),
            title="Vulnerable Code",
            border_color=SEVERITY_COLORS.get(get_field(finding, "severity", "Info"), SECONDARY),
        ))

    # Taint trace tree
    taint_trace = get_field(finding, "taint_trace", [])
    if taint_trace:
        console.print()
        console.print(taint_trace_tree(finding))

    console.print()
    console.print(f"  [dim]Run [cyan]devsecure remediation plan[/cyan] to generate a fix for this issue.[/dim]\n")
