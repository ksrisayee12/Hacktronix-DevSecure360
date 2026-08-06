"""
DevSecure360 CLI — Remediation Commands
==========================================
Commands: remediation plan | preview | apply | rollback

Workflow:
  1. plan    → generate AI fix for each finding (calls RemediationEngine)
  2. preview → show side-by-side diff of original vs patched code
  3. apply   → write patches to disk (with backup + confirmation)
  4. rollback → restore from backup
"""

from __future__ import annotations
import os
import re
import shutil
import time
from datetime import datetime
from typing import Optional

import typer
from rich.text import Text
from rich.syntax import Syntax
from rich.prompt import Confirm

from cli.theme import (
    console, make_panel, make_success_panel, make_error_panel, make_warning_panel,
    severity_icon, PRIMARY_CYAN, SUCCESS_COLOR, WARNING_COLOR, CRITICAL_COLOR, SECONDARY,
    SEVERITY_COLORS,
)
from cli.utils.session import get_session
from cli.utils.engine_bridge import run_remediation, get_field
from cli.utils.formatter import diff_view
from cli.utils.progress import remediation_progress, apply_progress, per_finding_progress

app = typer.Typer(help="AI-assisted vulnerability remediation")


# ─────────────────────────────────────────────
# devsecure remediation plan
# ─────────────────────────────────────────────

@app.command("plan")
def plan(
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Only remediate findings at this severity (Critical|High|Medium|Low)"
    ),
    max_findings: int = typer.Option(
        10, "--max", "-m", help="Maximum number of findings to remediate"
    ),
):
    """Generate an AI remediation plan for findings from the last scan."""
    session = get_session()

    if not isinstance(severity, str):
        severity = getattr(severity, "default", None)
        if not isinstance(severity, str):
            severity = None

    if not isinstance(max_findings, int):
        max_findings = getattr(max_findings, "default", 10)
        if not isinstance(max_findings, int):
            max_findings = 10

    if not session.scan_ran or not session.findings:
        console.print(make_warning_panel(
            Text("\n  No scan results in session.\n  Run [cyan]devsecure scan .[/cyan] first.\n"),
            title="No Findings",
        ))
        return

    # Filter findings to remediate
    findings = session.findings
    if severity:
        sev = severity.capitalize()
        findings = [f for f in findings if get_field(f, "severity", "") == sev]
        if not findings:
            console.print(make_warning_panel(
                Text(f"\n  No {sev} findings to remediate.\n"), title="Remediation Plan",
            ))
            return

    # Prioritize Critical → High → Medium → Low
    _sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings = sorted(
        findings,
        key=lambda f: _sev_order.get(get_field(f, "severity", "Info"), 5)
    )[:max_findings]

    console.print(f"\n[heading]  Generating remediation plan for {len(findings)} finding(s)...[/heading]\n")

    session.remediation_plan = []
    session.patched_files    = {}
    session.original_files   = {}

    progress = per_finding_progress(findings)
    task_id  = progress.add_task("Generating AI fixes", total=len(findings))

    with progress:
        for i, finding in enumerate(findings, 1):
            issue      = get_field(finding, "issue",    "")
            severity_v = get_field(finding, "severity", "")
            file_path  = get_field(finding, "file",     "")
            line       = get_field(finding, "line",     "")
            color      = SEVERITY_COLORS.get(severity_v, SECONDARY)

            progress.update(
                task_id,
                description=f"[{color}]{severity_icon(severity_v)} {severity_v}[/]  {issue[:55]}",
                advance=1,
            )

            # Read source file if available
            original_code = None
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                        original_code = fh.read()
                    session.original_files[file_path] = original_code
                except Exception:
                    pass

            # Call AI remediation engine
            try:
                raw_fix = run_remediation(finding, original_code)
            except Exception as e:
                raw_fix = f"# AI remediation failed: {e}"

            # Extract code block from markdown
            patched_code = _extract_code(raw_fix) or raw_fix

            session.remediation_plan.append({
                "finding":      finding,
                "raw_fix":      raw_fix,
                "patched_code": patched_code,
                "file_path":    file_path,
                "original":     original_code,
                "issue":        issue,
                "severity":     severity_v,
            })
            if file_path and patched_code:
                session.patched_files[file_path] = patched_code

    # Render plan summary
    console.print()
    content = Text()
    content.append(f"\n  Remediation Plan Generated\n\n", style=f"bold {PRIMARY_CYAN}")
    content.append(f"  Findings addressed: ", style=SECONDARY)
    content.append(f"{len(session.remediation_plan)}\n", style="bold white")

    for i, item in enumerate(session.remediation_plan, 1):
        sev   = item["severity"]
        issue = item["issue"]
        fpath = item["file_path"]
        color = SEVERITY_COLORS.get(sev, SECONDARY)
        content.append(f"\n  {i}. ", style=f"bold {PRIMARY_CYAN}")
        content.append(f"{severity_icon(sev)} [{sev}] ", style=f"bold {color}")
        content.append(f"{issue[:60]}\n",                style="white")
        if fpath:
            content.append(f"     → {os.path.basename(fpath)}\n", style=SECONDARY)

    content.append(f"\n  Run [bold cyan]devsecure remediation preview[/bold cyan] to review changes.\n")
    content.append(f"  Run [bold cyan]devsecure remediation apply[/bold cyan] to apply patches.\n\n")

    console.print(make_success_panel(content, title="Remediation Plan"))


# ─────────────────────────────────────────────
# devsecure remediation preview
# ─────────────────────────────────────────────

@app.command("preview")
def preview(
    index: Optional[int] = typer.Argument(None, help="Preview a specific fix (1-based index)"),
):
    """Preview the code diffs from the remediation plan."""
    session = get_session()

    if not session.remediation_plan:
        console.print(make_warning_panel(
            Text("\n  No remediation plan found.\n  Run [cyan]devsecure remediation plan[/cyan] first.\n"),
            title="No Plan",
        ))
        return

    items = session.remediation_plan
    if index is not None:
        if 1 <= index <= len(items):
            items = [items[index - 1]]
        else:
            console.print(make_error_panel(
                Text(f"\n  Index {index} out of range (1–{len(items)}).\n"),
            ))
            return

    console.print(f"\n[heading]  Remediation Preview — {len(items)} patch(es)[/heading]\n")

    for i, item in enumerate(items, 1):
        original    = item.get("original", "") or ""
        patched     = item.get("patched_code", "") or ""
        file_path   = item.get("file_path", "")
        filename    = os.path.basename(file_path) if file_path else "unknown"
        sev         = item.get("severity", "Info")
        issue       = item.get("issue", "")
        color       = SEVERITY_COLORS.get(sev, SECONDARY)

        header = Text()
        header.append(f"  {severity_icon(sev)} ", style=f"bold {color}")
        header.append(f"{issue}  ", style="bold white")
        header.append(f"→  {filename}", style=SECONDARY)

        console.print(make_panel(header, title=f"Patch #{i}", border_color=color))

        if original and patched and original.strip() != patched.strip():
            diff = diff_view(original, patched, filename=filename)
            console.print(make_panel(diff, title=f"Diff — {filename}", border_color=PRIMARY_CYAN))
        elif patched:
            ext  = filename.rsplit(".", 1)[-1].lower() if "." in filename else "python"
            lang_map = {"py": "python", "js": "javascript", "ts": "typescript",
                        "java": "java", "php": "php", "c": "c", "cpp": "cpp",
                        "go": "go", "cs": "csharp"}
            lang = lang_map.get(ext, "python")
            console.print(make_panel(
                Syntax(patched[:3000], lang, theme="monokai", line_numbers=True, word_wrap=True),
                title=f"Patched Code — {filename}",
                border_color=SUCCESS_COLOR,
            ))
        else:
            console.print(make_warning_panel(
                Text("\n  AI did not produce a patch for this finding.\n"),
            ))

        console.print()


# ─────────────────────────────────────────────
# devsecure remediation apply
# ─────────────────────────────────────────────

@app.command("apply")
def apply(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Apply the remediation patches to source files on disk."""
    session = get_session()

    if not isinstance(yes, bool):
        yes = getattr(yes, "default", False)
        if not isinstance(yes, bool):
            yes = False

    if not session.remediation_plan:
        console.print(make_warning_panel(
            Text("\n  No remediation plan found.\n  Run [cyan]devsecure remediation plan[/cyan] first.\n"),
            title="No Plan",
        ))
        return

    patchable = [
        item for item in session.remediation_plan
        if item.get("file_path") and item.get("patched_code")
    ]

    if not patchable:
        console.print(make_warning_panel(
            Text("\n  No file patches available in the plan.\n"),
        ))
        return

    # Confirmation
    console.print(f"\n[warning]  About to patch {len(patchable)} file(s) on disk.[/warning]\n")
    for item in patchable:
        console.print(f"    → {item['file_path']}")
    console.print()

    if not yes:
        confirmed = Confirm.ask("  Apply all patches?", default=False)
        if not confirmed:
            console.print(f"\n  [dim]Aborted. No files were modified.[/dim]\n")
            return

    # Backup and apply
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(os.getcwd(), "cli", "reports", f"backup_{timestamp}")
    os.makedirs(backup_dir, exist_ok=True)

    applied = 0
    failed  = []

    with apply_progress():
        for item in patchable:
            fp      = item["file_path"]
            patched = item["patched_code"]
            orig    = item.get("original", "")

            try:
                # Backup original
                if os.path.exists(fp) and orig:
                    rel = os.path.relpath(fp, os.getcwd())
                    bk  = os.path.join(backup_dir, rel.replace(os.sep, "_"))
                    with open(bk, "w", encoding="utf-8") as f:
                        f.write(orig)

                # Write patch
                with open(fp, "w", encoding="utf-8") as f:
                    f.write(patched)
                applied += 1
            except Exception as e:
                failed.append((fp, str(e)))

    # Result panel
    content = Text()
    content.append(f"\n  Patches Applied:  ", style=SECONDARY)
    content.append(f"{applied}\n", style=f"bold {SUCCESS_COLOR}")
    if failed:
        content.append(f"  Failed:           ", style=SECONDARY)
        content.append(f"{len(failed)}\n\n", style=f"bold {CRITICAL_COLOR}")
        for fp, err in failed:
            content.append(f"  ✗ {fp}: {err}\n", style=f"bold {CRITICAL_COLOR}")
    content.append(f"\n  Backup stored in:\n  {backup_dir}\n\n", style=SECONDARY)
    content.append(f"  Run [bold cyan]devsecure validate[/bold cyan] to confirm fixes.\n")
    content.append(f"  Run [bold cyan]devsecure remediation rollback[/bold cyan] to undo.\n\n")

    session.remediation_applied = True
    session._backup_dir = backup_dir

    console.print(make_success_panel(content, title="Patches Applied") if not failed
                  else make_warning_panel(content, title="Partially Applied"))


# ─────────────────────────────────────────────
# devsecure remediation rollback
# ─────────────────────────────────────────────

@app.command("rollback")
def rollback(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Restore original source files from the last backup."""
    session = get_session()
    backup_dir = getattr(session, "_backup_dir", None)

    if not backup_dir or not os.path.exists(backup_dir):
        # Try to find most recent backup
        reports_dir = os.path.join(os.getcwd(), "cli", "reports")
        if os.path.exists(reports_dir):
            backups = sorted([
                d for d in os.listdir(reports_dir)
                if d.startswith("backup_")
            ], reverse=True)
            if backups:
                backup_dir = os.path.join(reports_dir, backups[0])

    if not backup_dir or not os.path.exists(backup_dir):
        console.print(make_error_panel(
            Text("\n  No backup found. Run [cyan]devsecure remediation apply[/cyan] first.\n"),
        ))
        return

    console.print(f"\n[warning]  Restoring from backup: {backup_dir}[/warning]\n")
    if not yes:
        confirmed = Confirm.ask("  Restore all original files?", default=False)
        if not confirmed:
            console.print(f"\n  [dim]Rollback aborted.[/dim]\n")
            return

    restored = 0
    for fname in os.listdir(backup_dir):
        bk_path = os.path.join(backup_dir, fname)
        # Map backup filename back to original path
        orig_path = fname.replace("_", os.sep)
        if not os.path.isabs(orig_path):
            orig_path = os.path.join(os.getcwd(), orig_path)
        if os.path.exists(bk_path):
            try:
                shutil.copy2(bk_path, orig_path)
                restored += 1
            except Exception:
                pass

    console.print(make_success_panel(
        Text(f"\n  Restored {restored} file(s) from backup.\n", style="white"),
        title="Rollback Complete",
    ))


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _extract_code(text: str) -> Optional[str]:
    """Extract code from a markdown code block."""
    blocks = re.findall(r'```(?:[a-zA-Z]*)?\n(.*?)\n```', text or "", re.DOTALL)
    if blocks:
        return max(blocks, key=len).strip()
    return None
