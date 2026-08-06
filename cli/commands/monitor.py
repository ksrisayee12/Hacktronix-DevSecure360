"""
DevSecure360 CLI — Monitor Commands
======================================
Commands: watch, diff, commit-check
"""

from __future__ import annotations
import os
import time
from typing import Optional

import typer
from rich.text import Text
from rich.rule import Rule

from cli.theme import (
    console, make_panel, make_success_panel, make_error_panel, make_warning_panel,
    severity_icon, PRIMARY_CYAN, SUCCESS_COLOR, WARNING_COLOR, CRITICAL_COLOR, SECONDARY,
)

app = typer.Typer(help="File monitoring and CI/CD integration")


# ─────────────────────────────────────────────
# devsecure watch [path]
# ─────────────────────────────────────────────

@app.command("watch")
def watch(
    target: str = typer.Argument(".", help="Directory to monitor"),
    debounce: float = typer.Option(2.0, "--debounce", help="Seconds to wait before re-scanning"),
):
    """Watch a directory and auto-scan on file changes."""
    if not isinstance(target, str):
        target = getattr(target, "default", ".")
        if not isinstance(target, str):
            target = "."

    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        console.print(make_error_panel(
            Text("\n  watchdog is not installed.\n  pip install watchdog\n"),
        ))
        raise typer.Exit(1)

    from cli.commands.scan import _do_sast_scan

    abs_target = os.path.abspath(target)
    SKIP_EXTS  = {".pyc", ".pyo", ".log", ".tmp", ".swp"}
    WATCH_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".c", ".cpp", ".go", ".cs"}

    last_scan_time = [0.0]

    class ChangeHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if event.is_directory:
                return
            ext = os.path.splitext(event.src_path)[1].lower()
            if ext not in WATCH_EXTS or ext in SKIP_EXTS:
                return
            now = time.time()
            if now - last_scan_time[0] < debounce:
                return
            last_scan_time[0] = now
            rel = os.path.relpath(event.src_path, abs_target)
            console.print(f"\n[heading]  Change detected:[/heading] [white]{rel}[/white]")
            try:
                _do_sast_scan(abs_target)
            except SystemExit:
                pass

        on_created = on_modified

    observer = Observer()
    observer.schedule(ChangeHandler(), abs_target, recursive=True)
    observer.start()

    console.print(make_panel(
        Text(f"\n  Watching: {abs_target}\n  Press Ctrl+C to stop.\n", style="white"),
        title="DevSecure Watch",
    ))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        console.print(f"\n  [dim]Watch stopped.[/dim]\n")
    observer.join()


# ─────────────────────────────────────────────
# devsecure diff
# ─────────────────────────────────────────────

@app.command("diff")
def diff(
    base: str = typer.Option("HEAD", "--base", "-b", help="Base git ref (default: HEAD)"),
    target: str = typer.Option(".", "--target", "-t", help="Working directory"),
):
    """Scan only files changed vs a git ref (HEAD, branch, commit)."""
    if not isinstance(target, str):
        target = getattr(target, "default", ".")
        if not isinstance(target, str):
            target = "."

    if not isinstance(base, str):
        base = getattr(base, "default", "HEAD")
        if not isinstance(base, str):
            base = "HEAD"
    try:
        import git as gitmodule
    except ImportError:
        console.print(make_error_panel(
            Text("\n  gitpython is not installed.\n  pip install gitpython\n"),
        ))
        raise typer.Exit(1)

    from cli.commands.scan import _do_sast_scan

    abs_target = os.path.abspath(target)

    try:
        repo = gitmodule.Repo(abs_target, search_parent_directories=True)
    except Exception:
        console.print(make_error_panel(
            Text(f"\n  Not a git repository: {abs_target}\n"),
        ))
        raise typer.Exit(1)

    try:
        changed = repo.git.diff("--name-only", base).splitlines()
    except Exception as e:
        console.print(make_error_panel(
            Text(f"\n  git diff failed: {e}\n"),
        ))
        raise typer.Exit(1)

    src_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".c", ".cpp", ".go", ".cs"}
    src_files = [
        os.path.join(repo.working_dir, f)
        for f in changed
        if os.path.splitext(f)[1].lower() in src_exts
    ]

    if not src_files:
        console.print(make_success_panel(
            Text(f"\n  No source file changes detected vs {base}.\n"),
            title="Git Diff Scan",
        ))
        return

    content = Text()
    content.append(f"\n  Changed files vs {base}:\n\n", style=f"bold {PRIMARY_CYAN}")
    for fp in src_files:
        content.append(f"  → {os.path.relpath(fp, abs_target)}\n", style="white")
    content.append(f"\n  Scanning {len(src_files)} changed file(s)...\n")
    console.print(make_panel(content, title="Git Diff Scan"))

    # Write changed files to temp dir for targeted scan
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    try:
        for fp in src_files:
            rel = os.path.relpath(fp, repo.working_dir)
            dst = os.path.join(tmpdir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.exists(fp):
                shutil.copy2(fp, dst)
        _do_sast_scan(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────────────────────────
# devsecure commit-check
# ─────────────────────────────────────────────

@app.command("commit-check")
def commit_check(
    fail_on: str = typer.Option(
        "Critical", "--fail-on", help="Fail (exit 1) if findings at this severity exist"
    ),
):
    """
    Scan staged files — designed for use as a git pre-commit hook.
    Exits with code 1 if findings at or above --fail-on severity are found.

    \b
    Install as pre-commit hook:
      echo 'devsecure commit-check' >> .git/hooks/pre-commit
      chmod +x .git/hooks/pre-commit
    """
    try:
        import git as gitmodule
    except ImportError:
        console.print(make_error_panel(
            Text("\n  gitpython not installed.\n  pip install gitpython\n"),
        ))
        raise typer.Exit(1)

    from cli.commands.scan import _do_sast_scan
    from cli.utils.session import get_session
    from cli.utils.engine_bridge import get_field

    src_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".c", ".cpp", ".go", ".cs"}

    try:
        repo   = gitmodule.Repo(".", search_parent_directories=True)
        staged = repo.git.diff("--cached", "--name-only").splitlines()
    except Exception as e:
        console.print(make_error_panel(Text(f"\n  Git error: {e}\n")))
        raise typer.Exit(1)

    staged_src = [
        os.path.join(repo.working_dir, f)
        for f in staged
        if os.path.splitext(f)[1].lower() in src_exts
           and os.path.exists(os.path.join(repo.working_dir, f))
    ]

    if not staged_src:
        console.print(make_success_panel(
            Text("\n  No staged source files to check.\n  ✓  Pre-commit check passed.\n"),
            title="Commit Check",
        ))
        return

    console.print(f"\n[heading]  Commit Check — scanning {len(staged_src)} staged file(s)[/heading]\n")

    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    try:
        for fp in staged_src:
            rel = os.path.relpath(fp, repo.working_dir)
            dst = os.path.join(tmpdir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(fp, dst)

        _do_sast_scan(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    session = get_session()

    # Severity ordering — same as existing Severity enum
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    fail_rank  = sev_order.get(fail_on.capitalize(), 0)

    blocking = [
        f for f in session.findings
        if sev_order.get(get_field(f, "severity", "Info"), 5) <= fail_rank
    ]

    if blocking:
        console.print(make_error_panel(
            Text(
                f"\n  {len(blocking)} finding(s) at {fail_on} or above.\n"
                f"  Commit blocked.\n\n"
                f"  Run [cyan]devsecure explain[/cyan] for details.\n"
                f"  Run [cyan]devsecure remediation plan[/cyan] to fix.\n",
                style="white",
            ),
            title=f"Commit Blocked — {len(blocking)} Issue(s)",
        ))
        raise typer.Exit(1)
    else:
        console.print(make_success_panel(
            Text(f"\n  No {fail_on} or above findings detected.\n  ✓  Commit allowed.\n"),
            title="Commit Check Passed",
        ))
