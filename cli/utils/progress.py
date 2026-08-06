"""
DevSecure360 CLI — Progress Bar System
=========================================
Reusable Rich progress sequences for each workflow phase.
All phases correspond to the documented workflow:
  Scan → Analyze → Explain → Plan → Preview → Apply → Validate → Report
"""

from __future__ import annotations
import time
from contextlib import contextmanager
from typing import Generator

from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
    TaskProgressColumn,
)
from rich.live import Live
from rich.panel import Panel
from rich.console import Console

from cli.theme import PRIMARY_BLUE, PRIMARY_CYAN, console


# ─────────────────────────────────────────────
# PROGRESS BAR FACTORY
# ─────────────────────────────────────────────

def make_progress() -> Progress:
    """Creates a consistently styled Rich Progress instance."""
    return Progress(
        SpinnerColumn(spinner_name="dots", style=f"bold {PRIMARY_CYAN}"),
        TextColumn("[progress.text]{task.description}", style=f"{PRIMARY_CYAN}"),
        BarColumn(
            bar_width=40,
            style=PRIMARY_BLUE,
            complete_style=f"bold {PRIMARY_BLUE}",
            finished_style="bold #22C55E",
        ),
        TaskProgressColumn(style="bold #FFFFFF"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


# ─────────────────────────────────────────────
# SAST SCAN PROGRESS
# ─────────────────────────────────────────────

SAST_STAGES = [
    ("Collecting files",          0.08),
    ("Parsing source files",      0.15),
    ("Building AST",              0.15),
    ("Building CFG",              0.12),
    ("Running Rule Engine",       0.20),
    ("Taint Analysis",            0.15),
    ("AI Vulnerability Analysis", 0.10),
    ("Deduplicating findings",    0.05),
]


@contextmanager
def sast_progress(target: str) -> Generator[Progress, None, None]:
    """
    Context manager that shows animated SAST scan progress stages.
    Yields the Progress object so the caller can add extra tasks.

    Usage:
        with sast_progress("./myapp") as p:
            result = run_sast("./myapp")
    """
    progress = make_progress()
    with progress:
        for stage_name, weight in SAST_STAGES:
            task_id = progress.add_task(stage_name, total=100)
            # Animate in chunks
            steps = 20
            step_sleep = (weight * 0.8) / steps
            for i in range(steps):
                progress.update(task_id, advance=100 / steps)
                time.sleep(step_sleep)
            progress.update(task_id, completed=100)
        yield progress


# ─────────────────────────────────────────────
# REMEDIATION PROGRESS
# ─────────────────────────────────────────────

REMEDIATION_STAGES = [
    ("Analyzing vulnerabilities",   0.10),
    ("Generating AI fix plan",      0.25),
    ("Building code patches",       0.30),
    ("Validating patch syntax",     0.15),
    ("Preparing preview",           0.10),
    ("Writing remediation report",  0.10),
]

APPLY_STAGES = [
    ("Backing up original files",   0.10),
    ("Applying patches",            0.50),
    ("Verifying file integrity",    0.20),
    ("Updating scan history",       0.10),
    ("Cleanup",                     0.10),
]


@contextmanager
def remediation_progress(n_findings: int = 1) -> Generator[Progress, None, None]:
    """Context manager for remediation plan generation progress."""
    progress = make_progress()
    with progress:
        for stage_name, weight in REMEDIATION_STAGES:
            task_id = progress.add_task(stage_name, total=100)
            steps = 15
            step_sleep = (weight * 1.0) / steps
            for _ in range(steps):
                progress.update(task_id, advance=100 / steps)
                time.sleep(step_sleep)
            progress.update(task_id, completed=100)
        yield progress


@contextmanager
def apply_progress() -> Generator[Progress, None, None]:
    """Context manager for remediation apply progress."""
    progress = make_progress()
    with progress:
        for stage_name, weight in APPLY_STAGES:
            task_id = progress.add_task(stage_name, total=100)
            steps = 10
            step_sleep = (weight * 0.5) / steps
            for _ in range(steps):
                progress.update(task_id, advance=100 / steps)
                time.sleep(step_sleep)
            progress.update(task_id, completed=100)
        yield progress


# ─────────────────────────────────────────────
# REPORT PROGRESS
# ─────────────────────────────────────────────

REPORT_STAGES = [
    ("Collecting scan results",   0.15),
    ("Computing security score",  0.10),
    ("Formatting findings",       0.20),
    ("Building report structure", 0.25),
    ("Exporting report file",     0.20),
    ("Done",                      0.10),
]


@contextmanager
def report_progress(fmt: str = "json") -> Generator[Progress, None, None]:
    """Context manager for report generation progress."""
    progress = make_progress()
    with progress:
        for stage_name, weight in REPORT_STAGES:
            task_id = progress.add_task(stage_name, total=100)
            steps = 12
            step_sleep = (weight * 0.4) / steps
            for _ in range(steps):
                progress.update(task_id, advance=100 / steps)
                time.sleep(step_sleep)
            progress.update(task_id, completed=100)
        yield progress


# ─────────────────────────────────────────────
# VALIDATE PROGRESS
# ─────────────────────────────────────────────

VALIDATE_STAGES = [
    ("Loading patched files",       0.15),
    ("Re-running SAST engine",      0.50),
    ("Comparing before/after",      0.20),
    ("Computing delta score",       0.15),
]


@contextmanager
def validate_progress() -> Generator[Progress, None, None]:
    progress = make_progress()
    with progress:
        for stage_name, weight in VALIDATE_STAGES:
            task_id = progress.add_task(stage_name, total=100)
            steps = 10
            step_sleep = (weight * 0.6) / steps
            for _ in range(steps):
                progress.update(task_id, advance=100 / steps)
                time.sleep(step_sleep)
            progress.update(task_id, completed=100)
        yield progress


# ─────────────────────────────────────────────
# PER-FINDING PROGRESS (for remediation apply)
# ─────────────────────────────────────────────

def per_finding_progress(findings: list):
    """
    Returns a Progress instance configured for per-finding tracking.
    Used when applying remediation to N findings one-by-one.
    """
    return Progress(
        SpinnerColumn(spinner_name="dots", style=f"bold {PRIMARY_CYAN}"),
        TextColumn("[progress.text]{task.description}", style=PRIMARY_CYAN),
        BarColumn(bar_width=30, style=PRIMARY_BLUE, complete_style=f"bold {PRIMARY_BLUE}"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )
