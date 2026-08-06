"""
DevSecure360 CLI — Project Commands
======================================
Commands: init, status, config, doctor, version
"""

from __future__ import annotations
import os
import sys
import platform
from datetime import datetime

import typer
from rich.text import Text
from rich.table import Table

from cli.theme import (
    console, make_panel, make_success_panel, make_error_panel,
    status_icon, PRIMARY_CYAN, SUCCESS_COLOR, CRITICAL_COLOR, SECONDARY, LOGO, LOGO_SUBTITLE,
)
from cli.config import get_config
from cli.utils.engine_bridge import check_backend_health, get_history

app = typer.Typer(help="Project management commands")

CLI_VERSION = "1.0.0"
APP_VERSION = "0.1.0"


# ─────────────────────────────────────────────
# devsecure version
# ─────────────────────────────────────────────

@app.command("version")
def version():
    """Show DevSecure360 version information."""
    content = Text()
    content.append(f"\n  DevSecure360 CLI    ", style="bold white")
    content.append(f"v{CLI_VERSION}\n",         style=f"bold {PRIMARY_CYAN}")
    content.append(f"  Backend Engine      ", style="white")
    content.append(f"v{APP_VERSION}\n",         style=PRIMARY_CYAN)
    content.append(f"  Python              ", style="white")
    content.append(f"{sys.version.split()[0]}\n", style=PRIMARY_CYAN)
    content.append(f"  Platform            ", style="white")
    content.append(f"{platform.system()} {platform.machine()}\n", style=PRIMARY_CYAN)
    content.append(f"\n  License             MIT\n", style=f"dim {SECONDARY}")
    console.print(make_panel(content, title="Version"))


# ─────────────────────────────────────────────
# devsecure init
# ─────────────────────────────────────────────

@app.command("init")
def init(
    name: str = typer.Option(None, "--name", "-n", help="Project name"),
    path: str = typer.Option(".", "--path", "-p", help="Workspace root"),
):
    """Initialize a DevSecure360 workspace (.devsecure.toml)."""
    workspace = os.path.abspath(path)
    cfg = get_config(workspace)

    if cfg.exists:
        console.print(make_panel(
            Text(f"\n  .devsecure.toml already exists in:\n  {workspace}\n", style="white"),
            title="Already Initialized",
            border_color=PRIMARY_CYAN,
        ))
        return

    project_name = name or os.path.basename(workspace)
    ok = cfg.init_workspace(name=project_name)

    if ok:
        content = Text()
        content.append(f"\n  {status_icon(True)} Workspace initialized\n", style="bold white")
        content.append(f"\n  Project   ", style=SECONDARY)
        content.append(f"{project_name}\n", style="bold white")
        content.append(f"  Root      ", style=SECONDARY)
        content.append(f"{workspace}\n", style="white")
        content.append(f"  Config    ", style=SECONDARY)
        content.append(f".devsecure.toml\n\n", style="white")
        content.append(f"  Run [bold cyan]devsecure scan .[/bold cyan] to begin your first scan.\n")
        console.print(make_success_panel(content, title="Workspace Ready"))
    else:
        console.print(make_error_panel(
            Text("\n  Failed to write .devsecure.toml\n  Check write permissions.\n", style="white"),
        ))


# ─────────────────────────────────────────────
# devsecure status
# ─────────────────────────────────────────────

@app.command("status")
def status(
    path: str = typer.Option(".", "--path", "-p", help="Workspace root"),
):
    """Show workspace status and last scan summary."""
    workspace = os.path.abspath(path)
    cfg = get_config(workspace)
    history = get_history(limit=5)

    content = Text()
    content.append(f"\n  Workspace     ", style=SECONDARY)
    content.append(f"{workspace}\n", style="white")
    content.append(f"  Project       ", style=SECONDARY)
    content.append(f"{cfg.project_name}\n", style="bold white")
    content.append(
        f"  Config        ", style=SECONDARY
    )
    config_ok = cfg.exists
    config_label = "Found" if config_ok else "Not found (run devsecure init)"
    config_color = SUCCESS_COLOR if config_ok else WARNING_COLOR
    content.append("+ " if config_ok else "! ", style=f"bold {config_color}")
    content.append(f"{config_label}\n", style="white")
    content.append(f"\n  ── Recent Scans ──\n", style=f"bold {PRIMARY_CYAN}")

    if not history:
        content.append(f"  No scans recorded yet.\n", style=SECONDARY)
    else:
        for entry in history[:5]:
            ts      = entry.get("timestamp", "")[:19].replace("T", " ")
            scan_t  = entry.get("type", "sast").upper()
            score   = entry.get("score", "?")
            n_find  = len(entry.get("findings", []))
            content.append(f"  [{scan_t}]  ", style=f"bold {PRIMARY_CYAN}")
            content.append(f"{ts}  ", style=SECONDARY)
            content.append(f"Score: {score}  ", style="bold white")
            content.append(f"{n_find} finding{'s' if n_find != 1 else ''}\n", style="white")

    console.print(make_panel(content, title="Workspace Status"))


# ─────────────────────────────────────────────
# devsecure config
# ─────────────────────────────────────────────

@app.command("config")
def config_cmd(
    key:   str = typer.Argument(None, help="Config key (e.g. scan.parallel_workers)"),
    value: str = typer.Argument(None, help="Value to set"),
    path: str  = typer.Option(".", "--path", "-p"),
):
    """Show or set configuration values."""
    workspace = os.path.abspath(path)
    cfg = get_config(workspace)
    loaded = cfg.load()

    if key and value:
        parts = key.split(".")
        ok = cfg.set(*parts, value)
        if ok:
            console.print(f"[success]✓[/success]  Set [cyan]{key}[/cyan] = [white]{value}[/white]")
        else:
            console.print(f"[error]✗[/error]  Could not write config. Is tomli-w installed?")
        return

    if key:
        parts = key.split(".")
        val = cfg.get(*parts)
        console.print(f"[cyan]{key}[/cyan] = [white]{val}[/white]")
        return

    # Show full config table
    table = Table(
        title="[heading]Configuration[/heading]",
        show_header=True,
        header_style=f"bold {PRIMARY_CYAN}",
        border_style=PRIMARY_CYAN,
        show_lines=True,
    )
    table.add_column("Section",  style="bold white", width=14)
    table.add_column("Key",      style=PRIMARY_CYAN, width=22)
    table.add_column("Value",    style="white")

    def _flatten(d, prefix=""):
        for k, v in d.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                yield from _flatten(v, full_key)
            else:
                yield full_key, v

    for full_key, val in _flatten(loaded):
        parts = full_key.split(".")
        section = parts[0] if parts else ""
        key_name = ".".join(parts[1:]) if len(parts) > 1 else full_key
        table.add_row(section, key_name, str(val))

    console.print(table)


# ─────────────────────────────────────────────
# devsecure doctor
# ─────────────────────────────────────────────

@app.command("doctor")
def doctor():
    """Check DevSecure360 environment health."""
    from cli.utils.engine_bridge import check_backend_health

    console.print(f"\n[heading]  Running diagnostics...[/heading]\n")
    results = check_backend_health()

    content = Text()
    all_ok = True

    checks = {
        "SAST Engine":        results.get("SAST Engine", False),
        "Remediation Engine": results.get("Remediation Engine", False),
        "Score Aggregator":   results.get("Score Aggregator", False),
        "History DB":         results.get("History DB", False),
        "Ollama AI":          results.get("Ollama AI", False),
    }

    # System info
    content.append(f"\n  System\n",            style=f"bold {PRIMARY_CYAN}")
    content.append(f"  Python           ", style=SECONDARY)
    content.append(f"{sys.version.split()[0]}\n", style="white")
    content.append(f"  Platform         ", style=SECONDARY)
    content.append(f"{platform.system()} {platform.release()}\n", style="white")
    content.append(f"\n  Components\n",        style=f"bold {PRIMARY_CYAN}")

    for name, ok in checks.items():
        color = SUCCESS_COLOR if ok else CRITICAL_COLOR
        label = "OK  " if ok else "FAIL"
        content.append(f"  ", style="white")
        content.append("+ " if ok else "x ", style=f"bold {color}")
        content.append(f" {name:<22}", style="white")
        content.append(f"{label}\n", style=f"bold {color}")
        if not ok:
            all_ok = False

    # Recommendations
    if not checks.get("Ollama AI"):
        content.append(f"\n  ! Ollama is not running.\n", style=f"bold {CRITICAL_COLOR}")
        content.append(f"     AI remediation will be unavailable.\n", style=SECONDARY)
        content.append(f"     Start with: ollama serve\n", style=SECONDARY)

    if not all_ok:
        console.print(make_error_panel(content, title="Doctor -- Issues Found"))
    else:
        content.append(f"\n  All systems operational.\n", style=f"bold {SUCCESS_COLOR}")
        console.print(make_success_panel(content, title="Doctor -- All Clear"))
