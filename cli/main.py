"""
DevSecure360 CLI — Main Entrypoint
=====================================
Registered as the `devsecure` console script via setup.py.

Behavior:
  devsecure                → launches the interactive shell
  devsecure <command>      → runs a specific command and exits
  devsecure --help         → shows help
"""

from __future__ import annotations
import sys
import os

import typer
from rich.text import Text

# ── Register the backend package path before any imports ──────────────────────
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND   = os.path.join(_REPO_ROOT, "backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from cli.theme import (
    console, make_panel, LOGO, LOGO_SUBTITLE, PRIMARY_BLUE, PRIMARY_CYAN, SECONDARY,
)

# ── Import all command sub-apps ────────────────────────────────────────────────
from cli.commands.scan        import app as scan_app
from cli.commands.explain     import app as explain_app
from cli.commands.remediation import app as remediation_app
from cli.commands.validate    import app as validate_app
from cli.commands.report      import app as report_app
from cli.commands.monitor     import app as monitor_app
from cli.commands.project     import app as project_app
from cli.commands.dashboard   import app as dashboard_app


# ── Root Typer app ─────────────────────────────────────────────────────────────

app = typer.Typer(
    name="devsecure",
    help="DevSecure360 — AI-Powered Application Security CLI",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=False,   # We handle no-args ourselves (launch shell)
    pretty_exceptions_show_locals=False,
)


# ── Register sub-commands ──────────────────────────────────────────────────────

# Direct commands from sub-apps (flattened into root)
app.add_typer(scan_app,        name="scan",        help="Run SAST scan")
app.add_typer(explain_app,     name="explain",     help="Explain findings")
app.add_typer(remediation_app, name="remediation", help="AI remediation workflow")
app.add_typer(validate_app,    name="validate",    help="Validate patches")
app.add_typer(report_app,      name="report",      help="Generate reports")
app.add_typer(monitor_app,     name="monitor",     help="File monitoring")
app.add_typer(project_app,     name="project",     help="Project management")
app.add_typer(dashboard_app,   name="dashboard",   help="Open dashboard")


# ── Top-level convenience commands (mirrors of sub-app commands) ───────────────

@app.command("sast")
def sast_cmd(target: str = typer.Argument(".", help="Path to scan")):
    """Run SAST on a file or directory (alias for 'scan')."""
    from cli.commands.scan import _do_sast_scan
    _do_sast_scan(target)


@app.command("secrets")
def secrets_cmd(target: str = typer.Argument(".", help="Directory to scan")):
    """Scan for hardcoded secrets."""
    from cli.commands.scan import secrets
    secrets(target=target)


@app.command("deps")
def deps_cmd(target: str = typer.Argument(".", help="Directory to check")):
    """Scan dependency files."""
    from cli.commands.scan import deps
    deps(target=target)


@app.command("dast")
def dast_cmd(url: str = typer.Argument(..., help="Target URL")):
    """Run DAST on a URL."""
    from cli.commands.scan import dast
    dast(url=url)


@app.command("web")
def web_cmd(url: str = typer.Argument(..., help="Target URL")):
    """Alias for dast."""
    from cli.commands.scan import web
    web(url=url)


@app.command("port")
def port_cmd(
    host: str       = typer.Argument(..., help="Target host"),
    port_range: str = typer.Option("1-1024", "--range", "-r"),
):
    """Scan open ports on a host."""
    from cli.commands.scan import port
    port(host=host, port_range=port_range)


@app.command("watch")
def watch_cmd(target: str = typer.Argument(".", help="Directory to watch")):
    """Watch for file changes and auto-scan."""
    from cli.commands.monitor import watch
    watch(target=target)


@app.command("diff")
def diff_cmd(base: str = typer.Option("HEAD", "--base", "-b")):
    """Scan only git-changed files."""
    from cli.commands.monitor import diff
    diff(base=base)


@app.command("commit-check")
def commit_check_cmd(fail_on: str = typer.Option("Critical", "--fail-on")):
    """Pre-commit security gate."""
    from cli.commands.monitor import commit_check
    commit_check(fail_on=fail_on)


@app.command("init")
def init_cmd(
    name: str = typer.Option(None, "--name", "-n"),
    path: str = typer.Option(".", "--path", "-p"),
):
    """Initialize a DevSecure360 workspace."""
    from cli.commands.project import init
    init(name=name, path=path)


@app.command("status")
def status_cmd(path: str = typer.Option(".", "--path", "-p")):
    """Show workspace status."""
    from cli.commands.project import status
    status(path=path)


@app.command("config")
def config_cmd(
    key:   str = typer.Argument(None),
    value: str = typer.Argument(None),
    path:  str = typer.Option(".", "--path", "-p"),
):
    """View or set configuration values."""
    from cli.commands.project import config_cmd as _config_cmd
    _config_cmd(key=key, value=value, path=path)


@app.command("doctor")
def doctor_cmd():
    """Check DevSecure360 environment health."""
    from cli.commands.project import doctor
    doctor()


@app.command("version")
def version_cmd():
    """Show version information."""
    from cli.commands.project import version
    version()


@app.command("export")
def export_cmd(output: str = typer.Option(None, "--output", "-o")):
    """Export findings as CSV."""
    from cli.commands.report import export
    export(output=output)


# ── Callback: no args → launch interactive shell ───────────────────────────────

@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version and exit", is_eager=True),
):
    """
    DevSecure360 — AI-Powered Application Security CLI

    \b
    Run without arguments to launch the interactive shell.
    Run with a command to execute it directly.
    """
    if version:
        from cli import __version__
        console.print(f"[heading]DevSecure360 CLI[/heading]  [white]v{__version__}[/white]")
        raise typer.Exit(0)

    if ctx.invoked_subcommand is None:
        # No subcommand → launch interactive shell
        from cli.interactive.shell import run_shell
        run_shell()


# ── Public entrypoint called by setup.py ──────────────────────────────────────

def main():
    """Entry point registered as the `devsecure` console script."""
    app()


if __name__ == "__main__":
    main()
