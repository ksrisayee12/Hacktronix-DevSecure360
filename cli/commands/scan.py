"""
DevSecure360 CLI — Scan Commands
===================================
Commands: scan, sast, dast, web, port, secrets, deps
All scanning logic is delegated to the existing backend engines via engine_bridge.
"""

from __future__ import annotations
import os
import time

import typer
from rich.text import Text
from rich.rule import Rule

from cli.theme import (
    console, make_panel, make_success_panel, make_error_panel, make_warning_panel,
    severity_icon, PRIMARY_CYAN, SUCCESS_COLOR, WARNING_COLOR, CRITICAL_COLOR, SECONDARY,
)
from cli.utils.engine_bridge import run_sast, compute_security_score, get_field, findings_to_dicts
from cli.utils.session import get_session
from cli.utils.formatter import findings_to_table, score_to_panel, findings_summary_text
from cli.utils.progress import sast_progress

app = typer.Typer(help="Security scanning commands")


# ─────────────────────────────────────────────
# INTERNAL: run a SAST scan with full UI
# ─────────────────────────────────────────────

def _do_sast_scan(target: str):
    """Run SAST, update session, render results."""
    session = get_session()
    if not isinstance(target, str):
        target = getattr(target, "default", ".")
        if not isinstance(target, str):
            target = "."
    abs_target = os.path.abspath(target)

    if not os.path.exists(abs_target):
        console.print(make_error_panel(
            Text(f"\n  Path not found: {abs_target}\n", style="white"),
        ))
        raise typer.Exit(1)

    console.print(f"\n[heading]  Scanning:[/heading] [white]{abs_target}[/white]\n")

    # Show animated progress while running
    from concurrent.futures import ThreadPoolExecutor
    scan_result_holder = {}

    def _scan_task():
        try:
            result = run_sast(abs_target)
            scan_result_holder["result"] = result
        except Exception as e:
            scan_result_holder["error"] = str(e)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_scan_task)
        with sast_progress(abs_target):
            future.result()

    if "error" in scan_result_holder:
        console.print(make_error_panel(
            Text(f"\n  Scan failed:\n  {scan_result_holder['error']}\n", style="white"),
        ))
        raise typer.Exit(1)

    result = scan_result_holder["result"]
    findings_dicts = findings_to_dicts(result.findings)

    # Update session
    session.last_scan_result = result
    session.findings         = findings_dicts
    session.scan_target      = abs_target
    session.score            = result.score or compute_security_score(findings_dicts)
    session.scan_ran         = True

    _render_scan_results(findings_dicts, session.score, abs_target)


def _render_scan_results(findings: list, score: dict, target: str):
    """Render the full scan results UI."""
    console.print()

    # Score + Summary side by side
    score_panel = score_to_panel(score, target=os.path.basename(target))

    # Summary text
    summary_content = Text()
    summary_content.append(f"\n  Scan Complete\n\n",   style=f"bold {PRIMARY_CYAN}")
    summary_content.append(findings_summary_text(findings))
    summary_content.append(f"\n\n")

    if not findings:
        summary_content.append(f"  ✓  No vulnerabilities found.\n",   style=f"bold {SUCCESS_COLOR}")
        summary_content.append(f"  Your code looks clean!\n\n",        style=SECONDARY)
    else:
        summary_content.append(f"\n  Run [bold cyan]devsecure explain[/bold cyan] to review findings.\n")
        summary_content.append(f"  Run [bold cyan]devsecure remediation plan[/bold cyan] to generate fixes.\n\n")

    from rich.columns import Columns
    console.print(Columns([
        score_panel,
        make_panel(summary_content, title="Scan Summary"),
    ]))

    if findings:
        console.print()
        console.print(findings_to_table(findings[:20], title=f"Top Findings  ({len(findings)} total)"))

        if len(findings) > 20:
            console.print(f"\n  [dim]... and {len(findings) - 20} more. Use [cyan]devsecure explain[/cyan] to see all.[/dim]")

    console.print()


# ─────────────────────────────────────────────
# devsecure scan [target]
# ─────────────────────────────────────────────

@app.command("scan")
def scan(
    target: str = typer.Argument(".", help="File or directory to scan"),
    severity: str = typer.Option(None, "--severity", "-s", help="Filter output: Critical|High|Medium|Low"),
):
    """Run a full SAST security scan on a file or directory."""
    _do_sast_scan(target)


# ─────────────────────────────────────────────
# devsecure sast [target]
# ─────────────────────────────────────────────

@app.command("sast")
def sast(
    target: str = typer.Argument(".", help="File or directory to scan"),
):
    """Run Static Application Security Testing (SAST)."""
    _do_sast_scan(target)


# ─────────────────────────────────────────────
# devsecure secrets
# ─────────────────────────────────────────────

@app.command("secrets")
def secrets(
    target: str = typer.Argument(".", help="Directory to scan for secrets"),
):
    """Scan for hardcoded secrets, API keys, and credentials."""
    session = get_session()

    # The SAST engine already scans for secrets (AdvancedSecretScanner is wired in).
    # Run a normal SAST scan and filter for secret-related findings.
    console.print(f"\n[heading]  Scanning for secrets:[/heading] [white]{os.path.abspath(target)}[/white]\n")
    _do_sast_scan(target)

    # Filter for secret findings
    secret_vulns = {"Hardcoded Secret", "Weak Crypto", "Hardcoded Password", "API Key"}
    secret_findings = [
        f for f in session.findings
        if get_field(f, "vuln_class", "") in secret_vulns
        or "secret" in get_field(f, "rule_id", "").lower()
        or "hardcoded" in get_field(f, "issue", "").lower()
    ]

    if secret_findings:
        console.print(f"\n[warning]  Found {len(secret_findings)} secret-related finding(s)[/warning]\n")
        console.print(findings_to_table(secret_findings, title="Secrets & Credentials"))
    else:
        console.print(make_success_panel(
            Text("\n  No hardcoded secrets detected.\n", style="white"),
            title="Secrets Scan",
        ))


# ─────────────────────────────────────────────
# devsecure deps
# ─────────────────────────────────────────────

@app.command("deps")
def deps(
    target: str = typer.Argument(".", help="Directory to check for dependency issues"),
):
    """Scan dependency files for known vulnerability patterns."""
    import glob

    abs_target = os.path.abspath(target)
    dep_files = []

    # Discover dependency files
    patterns = [
        "requirements*.txt", "package.json", "package-lock.json",
        "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock",
        "pom.xml", "build.gradle", "go.mod", "Gemfile", "Cargo.toml",
    ]
    for pat in patterns:
        dep_files.extend(glob.glob(os.path.join(abs_target, "**", pat), recursive=True))

    content = Text()
    content.append(f"\n  Dependency Scan\n\n", style=f"bold {PRIMARY_CYAN}")

    if not dep_files:
        content.append("  No dependency files found.\n", style=SECONDARY)
        console.print(make_panel(content, title="Dependencies"))
        return

    for dp in dep_files:
        rel = os.path.relpath(dp, abs_target)
        content.append(f"  ✓  ", style=f"bold {SUCCESS_COLOR}")
        content.append(f"{rel}\n", style="white")

    content.append(f"\n  Found {len(dep_files)} dependency file(s).\n", style="white")
    content.append(f"\n  ⚠  Full SCA (Software Composition Analysis) is planned for Phase 3.\n", style=f"bold {WARNING_COLOR}")
    content.append(f"     SAST scan covers insecure dependency usage patterns.\n", style=SECONDARY)
    content.append(f"     Run [cyan]devsecure scan .[/cyan] for full code analysis.\n", style=SECONDARY)

    console.print(make_panel(content, title="Dependency Files"))


# ─────────────────────────────────────────────
# devsecure dast <url>
# ─────────────────────────────────────────────

@app.command("dast")
def dast(url: str = typer.Argument(..., help="Target URL for DAST scan")):
    """Run Dynamic Application Security Testing (DAST) on a URL."""
    _stub_dast(url, "DAST")


@app.command("web")
def web(url: str = typer.Argument(..., help="Target URL for web scan")):
    """Alias for dast — scan a web application URL."""
    _stub_dast(url, "Web")


def _stub_dast(url: str, label: str):
    content = Text()
    content.append(f"\n  {label} Engine\n\n",     style=f"bold {PRIMARY_CYAN}")
    content.append(f"  Target   ", style=SECONDARY)
    content.append(f"{url}\n\n", style="white")
    content.append(f"  Status   ", style=SECONDARY)
    content.append(f"Coming in Phase 5\n\n", style=f"bold {WARNING_COLOR}")
    content.append(f"  The DAST engine (Playwright-based) is implemented in the\n", style=SECONDARY)
    content.append(f"  backend but not yet wired into the main API (see main.py line 22).\n", style=SECONDARY)
    content.append(f"  SAST scanning covers server-side vulnerabilities in the meantime.\n", style=SECONDARY)
    console.print(make_warning_panel(content, title=f"{label} Scan"))


# ─────────────────────────────────────────────
# devsecure port <host>
# ─────────────────────────────────────────────

@app.command("port")
def port(
    host: str       = typer.Argument(..., help="Target host for port scan"),
    port_range: str = typer.Option("1-1024", "--range", "-r", help="Port range"),
):
    """Scan open ports on a target host."""
    content = Text()
    content.append(f"\n  Port Scanner\n\n",   style=f"bold {PRIMARY_CYAN}")
    content.append(f"  Host     ", style=SECONDARY)
    content.append(f"{host}\n",   style="white")
    content.append(f"  Range    ", style=SECONDARY)
    content.append(f"{port_range}\n\n", style="white")
    content.append(f"  Status   ", style=SECONDARY)
    content.append(f"Coming in Phase 3\n\n", style=f"bold {WARNING_COLOR}")
    content.append(f"  The PortScanner module exists in backend/app/scanner/port/\n", style=SECONDARY)
    content.append(f"  and will be wired in Phase 3.\n", style=SECONDARY)
    console.print(make_warning_panel(content, title="Port Scan"))
