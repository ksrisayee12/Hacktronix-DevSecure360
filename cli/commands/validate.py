"""
DevSecure360 CLI — Validate Command
======================================
Re-runs the SAST engine on patched files and compares before/after finding counts.
"""

from __future__ import annotations
import os
from concurrent.futures import ThreadPoolExecutor

import typer
from rich.text import Text
from rich.table import Table

from cli.theme import (
    console, make_panel, make_success_panel, make_error_panel, make_warning_panel,
    severity_icon, PRIMARY_CYAN, SUCCESS_COLOR, WARNING_COLOR, CRITICAL_COLOR, SECONDARY,
    SEVERITY_COLORS,
)
from cli.utils.session import get_session
from cli.utils.engine_bridge import run_sast, compute_security_score, get_field, findings_to_dicts
from cli.utils.progress import validate_progress
from cli.utils.formatter import score_to_panel, findings_to_table

app = typer.Typer(help="Validate remediation results")


@app.command("validate")
def validate():
    """Re-run SAST on patched files and show before/after comparison."""
    session = get_session()

    if not session.scan_ran:
        console.print(make_warning_panel(
            Text("\n  No previous scan in session.\n  Run [cyan]devsecure scan .[/cyan] first.\n"),
            title="No Baseline",
        ))
        return

    if not session.scan_target:
        console.print(make_error_panel(
            Text("\n  Scan target is unknown. Please re-run the scan.\n"),
        ))
        return

    before_findings = session.findings or []
    before_score    = session.score or compute_security_score(before_findings)

    console.print(f"\n[heading]  Re-scanning patched code...[/heading]\n")
    console.print(f"  Target: [white]{session.scan_target}[/white]\n")

    result_holder: dict = {}

    def _scan():
        try:
            result_holder["result"] = run_sast(session.scan_target)
        except Exception as e:
            result_holder["error"] = str(e)

    with ThreadPoolExecutor(max_workers=1) as executor:
        fut = executor.submit(_scan)
        with validate_progress():
            fut.result()

    if "error" in result_holder:
        console.print(make_error_panel(
            Text(f"\n  Validation scan failed:\n  {result_holder['error']}\n"),
        ))
        return

    result          = result_holder["result"]
    after_findings  = findings_to_dicts(result.findings)
    after_score     = result.score or compute_security_score(after_findings)

    # ── Before / After comparison ──────────────────────────────────────────────
    console.print()

    # Score delta
    b_score = before_score.get("score", 0)
    a_score = after_score.get("score", 0)
    delta   = a_score - b_score
    delta_str = f"+{delta}" if delta >= 0 else str(delta)
    delta_color = SUCCESS_COLOR if delta >= 0 else CRITICAL_COLOR

    # Findings delta
    b_count = len(before_findings)
    a_count = len(after_findings)
    fixed   = max(0, b_count - a_count)
    new_f   = max(0, a_count - b_count)

    # Comparison table
    table = Table(
        title="[heading]Before vs After Remediation[/heading]",
        show_header=True,
        header_style=f"bold {PRIMARY_CYAN}",
        border_style=PRIMARY_CYAN,
        show_lines=True,
    )
    table.add_column("Metric",          style="white",          width=20)
    table.add_column("Before",          style="white",          width=15)
    table.add_column("After",           style="white",          width=15)
    table.add_column("Delta",           width=12)

    def _delta_text(before: int, after: int, lower_is_better: bool = True) -> Text:
        d = after - before
        if d == 0:
            return Text("  ±0", style=SECONDARY)
        color = (SUCCESS_COLOR if d < 0 else CRITICAL_COLOR) if lower_is_better else \
                (SUCCESS_COLOR if d > 0 else CRITICAL_COLOR)
        sign  = "+" if d > 0 else ""
        return Text(f"  {sign}{d}", style=f"bold {color}")

    b_counts = before_score.get("counts", {})
    a_counts = after_score.get("counts",  {})

    table.add_row("Security Score",
                  str(b_score), str(a_score),
                  Text(f"  {delta_str}", style=f"bold {delta_color}"))
    table.add_row("Grade",
                  before_score.get("grade", "?"), after_score.get("grade", "?"),
                  Text(""))
    table.add_row("Total Findings",
                  str(b_count), str(a_count),
                  _delta_text(b_count, a_count))

    for sev in ["Critical", "High", "Medium", "Low"]:
        bc = b_counts.get(sev, 0)
        ac = a_counts.get(sev, 0)
        table.add_row(
            f"  {severity_icon(sev)} {sev}",
            str(bc), str(ac),
            _delta_text(bc, ac),
        )

    console.print(table)
    console.print()

    # Summary panel
    content = Text()
    content.append(f"\n  Validation Complete\n\n",         style=f"bold {PRIMARY_CYAN}")
    content.append(f"  Vulnerabilities fixed:  ", style=SECONDARY)
    content.append(f"{fixed}\n",                  style=f"bold {SUCCESS_COLOR}")
    if new_f:
        content.append(f"  New findings detected:  ", style=SECONDARY)
        content.append(f"{new_f}\n",               style=f"bold {WARNING_COLOR}")
    content.append(f"  Score delta:            ", style=SECONDARY)
    content.append(f"{delta_str}\n\n",             style=f"bold {delta_color}")

    if a_count == 0:
        content.append(f"  ✓  All vulnerabilities resolved!\n", style=f"bold {SUCCESS_COLOR}")
        content.append(f"     Run [cyan]devsecure report[/cyan] to generate the final report.\n")
    elif fixed > 0:
        content.append(f"  ✓  {fixed} finding(s) resolved. {a_count} remain.\n", style="white")
        content.append(f"     Run [cyan]devsecure remediation plan[/cyan] to address remaining issues.\n")
    else:
        content.append(f"  ⚠  No change detected.\n", style=f"bold {WARNING_COLOR}")
        content.append(f"     The patches may not have been applied, or issues remain.\n", style=SECONDARY)

    console.print(
        make_success_panel(content, title="Validation Result") if fixed > 0
        else make_warning_panel(content, title="Validation Result")
    )

    # Update session with new scan
    session.findings        = after_findings
    session.score           = after_score
    session.last_scan_result= result

    if after_findings:
        console.print()
        console.print(findings_to_table(after_findings[:15], title="Remaining Findings"))
    console.print()
