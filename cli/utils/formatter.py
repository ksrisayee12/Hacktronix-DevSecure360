"""
DevSecure360 CLI — Rich Output Formatter
=========================================
Converts Finding objects / dicts into Rich tables, panels, trees, and diffs.
Severity labels exactly match the existing Severity enum in shared/types.py:
    Critical | High | Medium | Low | Info
"""

from __future__ import annotations
import os
import textwrap
from typing import List, Optional

from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich.tree import Tree
from rich.columns import Columns
from rich.rule import Rule

from cli.theme import (
    console,
    make_panel,
    severity_badge,
    severity_color,
    severity_icon,
    grade_color,
    PRIMARY_CYAN,
    PRIMARY_BLUE,
    SUCCESS_COLOR,
    WARNING_COLOR,
    CRITICAL_COLOR,
    SECONDARY,
    SEVERITY_COLORS,
)
from cli.utils.engine_bridge import get_field


# ─────────────────────────────────────────────
# FINDINGS TABLE
# ─────────────────────────────────────────────

def findings_to_table(findings: list, title: str = "Findings") -> Table:
    """
    Renders a Rich table of findings.
    Columns: # | Severity | Vuln Class | File | Line | CWE | OWASP | Confidence
    """
    table = Table(
        title=f"[heading]{title}[/heading]",
        show_header=True,
        header_style=f"bold {PRIMARY_CYAN}",
        border_style=PRIMARY_CYAN,
        show_lines=True,
        expand=True,
    )

    table.add_column("#",          style="bold white",    width=4,  no_wrap=True)
    table.add_column("Severity",   width=10, no_wrap=True)
    table.add_column("Class",      style="white",        width=18, no_wrap=True)
    table.add_column("File",       style=SECONDARY,      width=28, no_wrap=True)
    table.add_column("Line",       style="white",        width=6,  no_wrap=True)
    table.add_column("Issue",      style="white",        width=35)
    table.add_column("CWE",        style=SECONDARY,      width=10, no_wrap=True)
    table.add_column("CVSS",       style="white",        width=6,  no_wrap=True)

    for idx, f in enumerate(findings, start=1):
        severity   = get_field(f, "severity",   "Info")
        vuln_class = get_field(f, "vuln_class", "Unknown")
        file_path  = get_field(f, "file",       "") or get_field(f, "url", "")
        line       = get_field(f, "line",       "")
        issue      = get_field(f, "issue",      "")
        cwe        = get_field(f, "cwe",        "")
        cvss       = get_field(f, "cvss_score", None)

        # Shorten file path
        if file_path:
            file_path = os.path.basename(file_path) or file_path

        color = SEVERITY_COLORS.get(severity, SECONDARY)
        sev_cell = Text(f" {severity_icon(severity)} {severity} ", style=f"bold {color}")

        cvss_str = f"{cvss:.1f}" if cvss is not None else "—"

        table.add_row(
            str(idx),
            sev_cell,
            vuln_class,
            file_path or "—",
            str(line) if line else "—",
            textwrap.shorten(issue, width=50, placeholder="…"),
            cwe or "—",
            cvss_str,
        )

    return table


# ─────────────────────────────────────────────
# FINDING DETAIL PANEL
# ─────────────────────────────────────────────

def finding_to_panel(finding, index: int = 0) -> Panel:
    """
    Renders a detailed Rich panel for a single finding.
    Shows: severity, class, file, line, CWE, OWASP, issue, description,
           evidence (syntax highlighted), taint trace tree, remediation.
    """
    severity   = get_field(finding, "severity",    "Info")
    vuln_class = get_field(finding, "vuln_class",  "Unknown")
    file_path  = get_field(finding, "file",        "") or get_field(finding, "url", "—")
    line       = get_field(finding, "line",        "—")
    issue      = get_field(finding, "issue",       "—")
    description= get_field(finding, "description", "—")
    evidence   = get_field(finding, "evidence",    None)
    taint_trace= get_field(finding, "taint_trace", [])
    remediation= get_field(finding, "remediation", "—")
    cwe        = get_field(finding, "cwe",         "—")
    owasp      = get_field(finding, "owasp",       "—")
    cvss       = get_field(finding, "cvss_score",  None)
    confidence = get_field(finding, "confidence",  "—")
    finding_id = get_field(finding, "id",          "")

    color = SEVERITY_COLORS.get(severity, SECONDARY)

    content = Text()

    # ── Header ───────────────────────────────
    content.append(f"\n  {severity_icon(severity)}  ", style=f"bold {color}")
    content.append(f"{issue}\n", style=f"bold white")
    content.append(f"  {'─' * 70}\n", style=SECONDARY)

    # ── Meta grid ────────────────────────────
    meta_pairs = [
        ("Severity",   f"{severity}",                      color),
        ("Class",      vuln_class,                          "white"),
        ("File",       str(file_path) if file_path else "—","white"),
        ("Line",       str(line),                           "white"),
        ("CWE",        cwe or "—",                         PRIMARY_CYAN),
        ("OWASP",      owasp or "—",                       PRIMARY_CYAN),
        ("CVSS",       f"{cvss:.1f}" if cvss else "—",     color),
        ("Confidence", confidence,                          SECONDARY),
    ]
    for label, value, val_color in meta_pairs:
        content.append(f"  {label:<14}", style=f"bold {SECONDARY}")
        content.append(f"{value}\n",    style=f"{val_color}")

    # ── Description ──────────────────────────
    content.append(f"\n  {'─' * 70}\n", style=SECONDARY)
    content.append("  Description\n",   style=f"bold {PRIMARY_CYAN}")
    for line_txt in textwrap.wrap(description, width=80):
        content.append(f"  {line_txt}\n", style="white")

    # ── Evidence ─────────────────────────────
    if evidence and evidence.strip():
        content.append(f"\n  Evidence\n", style=f"bold {PRIMARY_CYAN}")

    # ── Taint Trace ──────────────────────────
    if taint_trace:
        content.append(f"\n  Taint Trace\n", style=f"bold {PRIMARY_CYAN}")
        for step in taint_trace:
            if isinstance(step, dict):
                s   = step.get("step", "")
                ln  = step.get("line", "")
                fn  = step.get("file", "")
                desc= step.get("description", "")
            else:
                s, ln, fn, desc = step.step, step.line, step.file, step.description
            content.append(f"  Step {s}", style=f"bold {PRIMARY_BLUE}")
            content.append(f"  (line {ln})  ", style=SECONDARY)
            content.append(f"{desc}\n", style="white")

    # ── Remediation ──────────────────────────
    content.append(f"\n  {'─' * 70}\n", style=SECONDARY)
    content.append("  Remediation\n",   style=f"bold {SUCCESS_COLOR}")
    for line_txt in textwrap.wrap(remediation, width=80):
        content.append(f"  {line_txt}\n", style="white")

    content.append(f"\n  ID: {finding_id}\n", style=f"dim {SECONDARY}")

    title = f"Finding #{index}  ·  {vuln_class}" if index else vuln_class
    return Panel(content, title=f"[heading]{title}[/heading]", border_style=color, padding=(0, 0))


# ─────────────────────────────────────────────
# SCORE PANEL
# ─────────────────────────────────────────────

def score_to_panel(score: dict, target: str = "") -> Panel:
    """
    Renders a security score + grade summary panel.
    score dict: {score: int, grade: str, counts: {...}, max_cvss: float}
    """
    val   = score.get("score",    0)
    grade = score.get("grade",    "F")
    counts= score.get("counts",   {})
    cvss  = score.get("max_cvss", 0.0)

    g_color = grade_color(grade)

    content = Text()
    content.append(f"\n   Security Score\n\n", style=f"bold {PRIMARY_CYAN}")
    content.append(f"   {val:>3} / 100   ", style=f"bold white")
    content.append(f"Grade {grade}\n\n",       style=f"bold {g_color}")

    # Score bar
    filled = int(val / 5)
    empty  = 20 - filled
    bar_color = SUCCESS_COLOR if val >= 75 else (WARNING_COLOR if val >= 50 else CRITICAL_COLOR)
    content.append("   [", style=SECONDARY)
    content.append("█" * filled,  style=f"bold {bar_color}")
    content.append("░" * empty,   style=SECONDARY)
    content.append("]\n\n", style=SECONDARY)

    # Severity counts
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    for sev in sev_order:
        n     = counts.get(sev, 0)
        color = SEVERITY_COLORS.get(sev, SECONDARY)
        icon  = severity_icon(sev)
        content.append(f"   {icon} {sev:<10}", style=f"bold {color}")
        content.append(f"{n:>3}\n", style="white")

    content.append(f"\n   Max CVSS:  {cvss:.1f}\n", style=f"{SECONDARY}")
    if target:
        content.append(f"   Target:    {target}\n", style=SECONDARY)

    border = SUCCESS_COLOR if val >= 75 else (WARNING_COLOR if val >= 50 else CRITICAL_COLOR)
    return Panel(content, title="[heading]Security Assessment[/heading]", border_style=border, width=40)


# ─────────────────────────────────────────────
# CODE DIFF VIEW
# ─────────────────────────────────────────────

def diff_view(original: str, patched: str, language: str = "python", filename: str = "") -> Text:
    """
    Produces a unified-diff style Rich Text output.
    Removed lines (─) in red, added lines (+) in green.
    """
    import difflib
    orig_lines  = original.splitlines(keepends=True)
    patch_lines = patched.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        orig_lines, patch_lines,
        fromfile=f"original/{filename}",
        tofile=f"patched/{filename}",
        lineterm="",
    ))

    text = Text()
    for line in diff:
        if line.startswith("+++") or line.startswith("---"):
            text.append(line + "\n", style=f"bold {SECONDARY}")
        elif line.startswith("@@"):
            text.append(line + "\n", style=f"bold {PRIMARY_CYAN}")
        elif line.startswith("+"):
            text.append(line + "\n", style=f"bold {SUCCESS_COLOR}")
        elif line.startswith("-"):
            text.append(line + "\n", style=f"bold {CRITICAL_COLOR}")
        else:
            text.append(line + "\n", style="white")

    return text


# ─────────────────────────────────────────────
# TAINT TRACE TREE
# ─────────────────────────────────────────────

def taint_trace_tree(finding) -> Tree:
    """Renders the taint trace as a Rich Tree."""
    issue = get_field(finding, "issue", "Vulnerability")
    tree  = Tree(f"[bold {PRIMARY_CYAN}]Taint Trace — {issue}[/]")

    taint_trace = get_field(finding, "taint_trace", [])
    for step in taint_trace:
        if isinstance(step, dict):
            s, ln, fn, desc = step.get("step"), step.get("line"), step.get("file",""), step.get("description","")
        else:
            s, ln, fn, desc = step.step, step.line, step.file, step.description
        node = tree.add(f"[bold {PRIMARY_BLUE}]Step {s}[/]  [dim]line {ln}[/]")
        node.add(f"[white]{desc}[/]")
    return tree


# ─────────────────────────────────────────────
# SUMMARY STATS TEXT
# ─────────────────────────────────────────────

def findings_summary_text(findings: list) -> Text:
    """One-line summary: '12 findings  ·  3 Critical  2 High  5 Medium  2 Low'"""
    from collections import Counter
    sev_counts = Counter()
    for f in findings:
        sev = get_field(f, "severity", "Info")
        sev_counts[sev] += 1

    text = Text()
    text.append(f"{len(findings)} finding{'s' if len(findings) != 1 else ''}  ·  ", style=f"bold white")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        n = sev_counts.get(sev, 0)
        if n:
            color = SEVERITY_COLORS.get(sev, SECONDARY)
            text.append(f"{n} {sev}  ", style=f"bold {color}")
    return text
