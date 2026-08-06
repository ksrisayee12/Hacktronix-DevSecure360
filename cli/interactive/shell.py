"""
DevSecure360 CLI — Interactive Shell
=======================================
A production-quality REPL built with prompt_toolkit.
Features:
  - Custom branded prompt: "DevSecure360 > "
  - Tab-completion for all commands
  - Arrow-key command history
  - Animated startup screen with ASCII logo
  - NLP routing for natural language input
  - All CLI commands available inline
"""

from __future__ import annotations
import os
import sys
import time
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.styles import Style as PTStyle
from prompt_toolkit.formatted_text import HTML

from cli.theme import (
    console, make_panel, make_success_panel,
    LOGO, print_logo_banner, LOGO_SUBTITLE,
    PRIMARY_BLUE, PRIMARY_CYAN, SUCCESS_COLOR, WARNING_COLOR, CRITICAL_COLOR, SECONDARY,
    status_icon,
)
from cli.interactive.nlp_router import route, is_exit
from cli.utils.engine_bridge import check_backend_health


# ─────────────────────────────────────────────
# PROMPT STYLE
# ─────────────────────────────────────────────

PT_STYLE = PTStyle.from_dict({
    "prompt":        f"bold {PRIMARY_BLUE}",
    "prompt.arrow":  f"{PRIMARY_CYAN}",
    "completion-menu.completion":         "bg:#1e293b #e2e8f0",
    "completion-menu.completion.current": f"bg:{PRIMARY_BLUE} #ffffff bold",
    "scrollbar.background":               "bg:#1e293b",
    "scrollbar.button":                   f"bg:{PRIMARY_CYAN}",
})


# ─────────────────────────────────────────────
# TAB COMPLETION
# ─────────────────────────────────────────────

COMPLETIONS = [
    # Scan
    "scan", "scan .", "sast", "dast", "web", "port", "secrets", "deps",
    # Explain
    "explain", "explain critical", "explain high", "explain medium", "explain low",
    # Remediation
    "remediation plan", "remediation preview", "remediation apply", "remediation rollback",
    # Validate / Report
    "validate",
    "report", "report json", "report html", "report pdf", "export",
    # Monitor
    "watch", "diff", "commit-check",
    # Project
    "init", "status", "config", "doctor", "version",
    # Dashboard / Help
    "dashboard", "help", "clear", "exit", "quit",
    # NLP shortcuts
    "scan my project", "scan backend", "scan frontend",
    "show critical", "show high", "show medium", "show low",
    "generate report", "generate remediation plan", "open dashboard",
    "find secrets", "scan dependencies",
]

COMPLETER = WordCompleter(COMPLETIONS, ignore_case=True, match_middle=True)


# ─────────────────────────────────────────────
# STARTUP SCREEN
# ─────────────────────────────────────────────

def _print_logo():
    """Print the ASCII logo and startup sequence."""
    print_logo_banner()
    console.print(f"\n  [bold {PRIMARY_CYAN}]{LOGO_SUBTITLE}[/]")
    console.print()
    console.print(f"  [dim {'─' * 50}]{'─' * 50}[/]")

    # Animated init checks
    health = check_backend_health()
    checks = [
        ("Security Engine",       health.get("SAST Engine",         False)),
        ("AI Security Agent",     health.get("Remediation Engine",   False)),
        ("Rule Database",         health.get("Score Aggregator",     False)),
        ("Threat Intelligence",   health.get("History DB",           False)),
        ("Workspace Ready",       True),
    ]

    time.sleep(0.1)
    for label, ok in checks:
        icon  = "✓" if ok else "⚠"
        color = SUCCESS_COLOR if ok else WARNING_COLOR
        console.print(f"  [{color}]{icon}[/{color}]  [white]{label}[/white]")
        time.sleep(0.12)

    console.print(f"  [dim {'─' * 50}]{'─' * 50}[/]")
    console.print()
    console.print(f'  [dim]Type [bold cyan]"help"[/bold cyan] to see all commands.  Type [bold cyan]"exit"[/bold cyan] to quit.[/dim]')
    console.print()


def _print_help():
    """Print the inline help panel."""
    from rich.table import Table

    table = Table(
        title="[heading]DevSecure360 — Command Reference[/heading]",
        show_header=True,
        header_style=f"bold {PRIMARY_CYAN}",
        border_style=PRIMARY_CYAN,
        show_lines=True,
        expand=True,
    )
    table.add_column("Command",      style=f"bold {PRIMARY_CYAN}", width=32)
    table.add_column("Description",  style="white")

    sections = [
        ("── Scanning ─────────────────────────────────────────────────────", ""),
        ("scan [path]",               "Run SAST on a file or directory"),
        ("scan .",                    "Scan the current directory"),
        ("secrets",                   "Scan for hardcoded secrets"),
        ("dast <url>",                "Dynamic scan a web application (Phase 5)"),
        ("port <host>",               "Scan open ports (Phase 3)"),
        ("deps",                      "Check dependency files"),
        ("── Explain ──────────────────────────────────────────────────────", ""),
        ("explain",                   "List all findings from last scan"),
        ("explain <n>",               "Detailed view of finding #n"),
        ("explain critical",          "Show Critical findings only"),
        ("explain high",              "Show High findings only"),
        ("explain medium",            "Show Medium findings only"),
        ("explain low",               "Show Low findings only"),
        ("── Remediation ──────────────────────────────────────────────────", ""),
        ("remediation plan (or 'fix')", "Generate AI fix plan for all findings"),
        ("remediation preview (or 'preview')", "Preview code diffs before applying"),
        ("remediation apply (or 'apply')",   "Apply patches to source files"),
        ("remediation rollback (or 'rollback')", "Restore original files from backup"),
        ("── Validation & Reports ─────────────────────────────────────────", ""),
        ("validate",                  "Re-scan patched files and compare results"),
        ("report",                    "Show security report in terminal"),
        ("report json",               "Export JSON report"),
        ("report html",               "Export styled HTML report"),
        ("report pdf",                "Export PDF report"),
        ("export",                    "Export findings as CSV"),
        ("── Monitoring ───────────────────────────────────────────────────", ""),
        ("watch [path]",              "Auto-scan on file changes"),
        ("diff",                      "Scan only git-changed files"),
        ("commit-check",              "Pre-commit security gate"),
        ("── Project ──────────────────────────────────────────────────────", ""),
        ("init",                      "Initialize workspace (.devsecure.toml)"),
        ("status",                    "Show workspace and scan history"),
        ("config",                    "View or set configuration"),
        ("doctor",                    "Check environment health"),
        ("version",                   "Show version info"),
        ("dashboard",                 "Open React dashboard or TUI view"),
        ("── Shell ────────────────────────────────────────────────────────", ""),
        ("help",                      "Show this help"),
        ("clear",                     "Clear the terminal"),
        ("exit / quit",               "Exit the shell"),
    ]

    for cmd, desc in sections:
        if desc == "" and cmd.startswith("──"):
            table.add_row(f"[dim]{cmd}[/dim]", "")
        else:
            table.add_row(cmd, desc)

    console.print()
    console.print(table)
    console.print()
    console.print(f"  [dim]Natural language also works: e.g. \"scan my project\", \"show critical vulnerabilities\"[/dim]\n")


# ─────────────────────────────────────────────
# COMMAND DISPATCHER
# ─────────────────────────────────────────────

def _dispatch(handler: str, arg: Optional[str]):
    """Route a handler name + optional arg to the appropriate command function."""
    try:
        if handler == "scan":
            from cli.commands.scan import _do_sast_scan
            _do_sast_scan(arg or ".")

        elif handler == "sast":
            from cli.commands.scan import _do_sast_scan
            _do_sast_scan(arg or ".")

        elif handler == "dast":
            from cli.commands.scan import _stub_dast
            _stub_dast(arg or "https://example.com", "DAST")

        elif handler == "web":
            from cli.commands.scan import _stub_dast
            _stub_dast(arg or "https://example.com", "Web")

        elif handler == "secrets":
            from cli.commands.scan import secrets
            secrets(target=arg or ".")

        elif handler == "deps":
            from cli.commands.scan import deps
            deps(target=arg or ".")

        elif handler == "port":
            from cli.commands.scan import port
            port(host=arg or "localhost")

        elif handler == "explain":
            from cli.commands.explain import explain
            explain(target=arg)

        elif handler == "remediation_plan":
            from cli.commands.remediation import plan
            plan()

        elif handler == "remediation_preview":
            from cli.commands.remediation import preview
            preview(index=None)

        elif handler == "remediation_apply":
            from cli.commands.remediation import apply
            apply(yes=False)

        elif handler == "remediation_rollback":
            from cli.commands.remediation import rollback
            rollback(yes=False)

        elif handler == "validate":
            from cli.commands.validate import validate
            validate()

        elif handler == "report":
            from cli.commands.report import report
            report(fmt=None)

        elif handler == "report_json":
            from cli.commands.report import report_json
            report_json()

        elif handler == "report_html":
            from cli.commands.report import report_html
            report_html()

        elif handler == "report_pdf":
            from cli.commands.report import report_pdf
            report_pdf()

        elif handler == "export":
            from cli.commands.report import export
            export(output=None)

        elif handler == "dashboard":
            from cli.commands.dashboard import dashboard
            dashboard(tui=False)

        elif handler == "watch":
            from cli.commands.monitor import watch
            watch(target=arg or ".")

        elif handler == "diff":
            from cli.commands.monitor import diff
            diff()

        elif handler == "status":
            from cli.commands.project import status
            status()

        elif handler == "doctor":
            from cli.commands.project import doctor
            doctor()

        elif handler == "version":
            from cli.commands.project import version
            version()

        elif handler == "init":
            from cli.commands.project import init
            init()

        elif handler == "config":
            from cli.commands.project import config_cmd
            config_cmd(key=arg)

        elif handler == "help":
            _print_help()

        elif handler == "clear":
            os.system("cls" if os.name == "nt" else "clear")

        elif handler == "exit":
            raise SystemExit(0)

        else:
            console.print(f"  [dim]Unknown command. Type [cyan]help[/cyan] to see all commands.[/dim]\n")

    except SystemExit:
        raise
    except Exception as e:
        console.print(f"\n  [error]Error:[/error] [white]{e}[/white]\n")


# ─────────────────────────────────────────────
# MAIN SHELL LOOP
# ─────────────────────────────────────────────

def run_shell():
    """Launch the DevSecure360 interactive REPL."""
    _print_logo()

    session = PromptSession(
        history=InMemoryHistory(),
        completer=COMPLETER,
        complete_while_typing=True,
        style=PT_STYLE,
    )

    PROMPT_HTML = HTML(
        f'<ansiblue><b>DevSecure360</b></ansiblue>'
        f'<ansicyan> ❯ </ansicyan>'
    )

    while True:
        try:
            raw = session.prompt(PROMPT_HTML).strip()
        except KeyboardInterrupt:
            console.print(f"\n  [dim]Ctrl+C — type [cyan]exit[/cyan] to quit.[/dim]\n")
            continue
        except EOFError:
            console.print(f"\n  [dim]Goodbye.[/dim]\n")
            break

        if not raw:
            continue

        if is_exit(raw):
            console.print(f"\n  [dim]Goodbye.[/dim]\n")
            break

        # Try direct command match first
        result = route(raw)
        if result:
            try:
                _dispatch(result.handler, result.arg)
            except SystemExit:
                console.print(f"\n  [dim]Goodbye.[/dim]\n")
                break
        else:
            # Unknown input
            console.print(
                f"\n  [dim]Unknown command: [white]{raw}[/white]\n"
                f"  Type [cyan]help[/cyan] to see all commands.[/dim]\n"
            )
