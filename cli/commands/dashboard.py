"""
DevSecure360 CLI — Dashboard Command
=======================================
Opens the React dashboard in the browser, or shows a TUI summary if unavailable.
"""

from __future__ import annotations
import os
import webbrowser

import typer
from rich.text import Text
from rich.table import Table
from rich.columns import Columns

from cli.theme import (
    console, make_panel, make_success_panel, make_warning_panel,
    PRIMARY_CYAN, SUCCESS_COLOR, WARNING_COLOR, SECONDARY, SEVERITY_COLORS, severity_icon,
)
from cli.utils.session import get_session
from cli.utils.engine_bridge import check_api_health, get_history, get_field
from cli.utils.formatter import score_to_panel, findings_to_table

app = typer.Typer(help="Open the DevSecure360 dashboard")

DASHBOARD_URL = os.getenv("DEVSECURE_DASHBOARD_URL", "http://localhost:3000")
API_URL       = os.getenv("DEVSECURE_API_URL",       "http://localhost:8000")


@app.command("dashboard")
def dashboard(
    tui: bool = typer.Option(False, "--tui", help="Force TUI mode even if browser is available"),
):
    """Open the DevSecure360 web dashboard or show a TUI summary."""
    if not isinstance(tui, bool):
        tui = getattr(tui, "default", False)
        if not isinstance(tui, bool):
            tui = False

    api_ok      = check_api_health()
    session     = get_session()

    if not tui:
        # Try to open browser
        try:
            webbrowser.open(DASHBOARD_URL)
            content = Text()
            content.append(f"\n  Opening dashboard in browser...\n\n", style=f"bold {PRIMARY_CYAN}")
            content.append(f"  URL     ", style=SECONDARY)
            content.append(f"{DASHBOARD_URL}\n",       style="bold white")
            content.append(f"  API     ", style=SECONDARY)
            content.append(
                f"{API_URL}  {'[success]● Online[/success]' if api_ok else '[error]● Offline[/error]'}\n",
                style="white"
            )
            console.print(make_success_panel(content, title="Dashboard"))
            return
        except Exception:
            pass

    # TUI fallback — show session summary
    _show_tui_dashboard(session, api_ok)


def _show_tui_dashboard(session, api_ok: bool):
    """Rich TUI dashboard showing current session state and history."""
    history = get_history(limit=10)

    # Status bar
    status_text = Text()
    status_text.append("  API  ", style=SECONDARY)
    status_text.append(
        "● Online\n" if api_ok else "● Offline\n",
        style=f"bold {SUCCESS_COLOR}" if api_ok else f"bold {WARNING_COLOR}",
    )
    status_text.append("  Mode  ", style=SECONDARY)
    status_text.append("TUI Dashboard\n", style="bold white")

    console.print()
    console.print(make_panel(status_text, title="DevSecure360 Dashboard"))
    console.print()

    # Current session findings
    if session.scan_ran and session.findings:
        score_panel = score_to_panel(session.score or {}, target=session.scan_target or "")
        summary = Text()
        summary.append("\n  Current Session\n\n",       style=f"bold {PRIMARY_CYAN}")
        summary.append(f"  Target    ", style=SECONDARY)
        summary.append(f"{session.scan_target or 'N/A'}\n", style="white")
        summary.append(f"  Findings  ", style=SECONDARY)
        summary.append(f"{len(session.findings)}\n",    style="bold white")
        summary.append(f"  Remediated", style=SECONDARY)
        summary.append(
            f"{'Yes' if session.remediation_applied else 'No'}\n",
            style=f"bold {SUCCESS_COLOR}" if session.remediation_applied else "white",
        )
        console.print(Columns([score_panel, make_panel(summary, title="Session")]))
        console.print()
        console.print(findings_to_table(session.findings[:10], title="Latest Findings"))
    else:
        console.print(make_panel(
            Text("\n  No active scan in session.\n  Run [cyan]devsecure scan .[/cyan] to begin.\n"),
            title="Session",
        ))

    # History table
    if history:
        console.print()
        hist_table = Table(
            title="[heading]Scan History[/heading]",
            show_header=True,
            header_style=f"bold {PRIMARY_CYAN}",
            border_style=PRIMARY_CYAN,
            show_lines=True,
        )
        hist_table.add_column("Time",     style=SECONDARY,  width=20)
        hist_table.add_column("Type",     style="white",    width=8)
        hist_table.add_column("Score",    style="white",    width=8)
        hist_table.add_column("Findings", style="white",    width=10)
        hist_table.add_column("Critical", style=f"bold {SEVERITY_COLORS['Critical']}", width=10)
        hist_table.add_column("High",     style=f"bold {SEVERITY_COLORS['High']}",     width=8)

        for entry in history:
            ts      = entry.get("timestamp", "")[:19].replace("T", " ")
            scan_t  = entry.get("type", "sast").upper()
            score_v = str(entry.get("score", "?"))
            finds   = entry.get("findings", [])
            n       = len(finds)
            crit    = sum(1 for f in finds if get_field(f, "severity", "") == "Critical")
            high    = sum(1 for f in finds if get_field(f, "severity", "") == "High")
            hist_table.add_row(ts, scan_t, score_v, str(n), str(crit) if crit else "—", str(high) if high else "—")

        console.print(hist_table)

    console.print()
    console.print(
        f"  [dim]Open [cyan]{DASHBOARD_URL}[/cyan] in your browser for the full React dashboard.[/dim]\n"
    )
