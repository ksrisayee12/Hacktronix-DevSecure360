"""
DevSecure360 CLI — Color Theme & Style System
===============================================
All colors and styles are derived from the existing Severity enum:
    Critical  → #EF4444 (Red)
    High      → #F59E0B (Amber)
    Medium    → #06B6D4 (Cyan)
    Low       → #22C55E (Green)
    Info      → #9CA3AF (Gray)

Panel borders, headings, and logo use:
    Primary Blue  → #2563EB
    Primary Cyan  → #06B6D4

This module is the SINGLE SOURCE OF TRUTH for all CLI visuals.
"""

from rich.style import Style
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.console import Console
from rich.theme import Theme

# ─────────────────────────────────────────────
# COLOR PALETTE
# ─────────────────────────────────────────────

PRIMARY_BLUE  = "#2563EB"
PRIMARY_CYAN  = "#06B6D4"
WHITE         = "#FFFFFF"

# Severity-based colors — names match Severity enum in shared/types.py exactly
SEVERITY_COLORS = {
    "Critical": "#EF4444",   # Red
    "High":     "#F59E0B",   # Amber
    "Medium":   "#06B6D4",   # Cyan
    "Low":      "#22C55E",   # Green
    "Info":     "#9CA3AF",   # Gray
}

SUCCESS_COLOR  = "#22C55E"  # Low / success / ok
WARNING_COLOR  = "#F59E0B"  # High / warning
CRITICAL_COLOR = "#EF4444"  # Critical / error
SECONDARY      = "#9CA3AF"  # Secondary text / Info

# ─────────────────────────────────────────────
# RICH THEME
# ─────────────────────────────────────────────

DS_THEME = Theme({
    # Brand
    "brand":         f"bold {PRIMARY_BLUE}",
    "heading":       f"bold {PRIMARY_CYAN}",
    "border":        PRIMARY_CYAN,
    "logo":          f"bold {PRIMARY_BLUE}",

    # Severity — exact enum value names
    "sev.Critical":  f"bold {SEVERITY_COLORS['Critical']}",
    "sev.High":      f"bold {SEVERITY_COLORS['High']}",
    "sev.Medium":    f"bold {SEVERITY_COLORS['Medium']}",
    "sev.Low":       f"bold {SEVERITY_COLORS['Low']}",
    "sev.Info":      f"{SEVERITY_COLORS['Info']}",

    # Status
    "success":       f"bold {SUCCESS_COLOR}",
    "warning":       f"bold {WARNING_COLOR}",
    "error":         f"bold {CRITICAL_COLOR}",
    "secondary":     SECONDARY,
    "info":          WHITE,

    # UI elements
    "progress.bar":  PRIMARY_BLUE,
    "progress.text": PRIMARY_CYAN,
    "dim":           SECONDARY,
})

# ─────────────────────────────────────────────
# CONSOLE (singleton, use this everywhere)
# ─────────────────────────────────────────────

import sys

# On Windows, force Rich to use the standard stdout with UTF-8 to avoid cp1252 errors
if sys.platform == "win32":
    import io
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
console = Console(theme=DS_THEME, highlight=False)

# ─────────────────────────────────────────────
# SEVERITY → STYLED TEXT
# ─────────────────────────────────────────────

def severity_badge(severity: str) -> Text:
    """Returns a colored Rich Text badge for a severity level.
    Severity names must match the existing Severity enum values:
    Critical, High, Medium, Low, Info
    """
    color = SEVERITY_COLORS.get(severity, SECONDARY)
    return Text(f" {severity} ", style=Style(color=color, bold=True))


def severity_color(severity: str) -> str:
    """Returns the hex color string for the given severity name."""
    return SEVERITY_COLORS.get(severity, SECONDARY)


# ─────────────────────────────────────────────
# PANEL BUILDERS
# ─────────────────────────────────────────────

def make_panel(content, title: str = "", subtitle: str = "", border_color: str = PRIMARY_CYAN) -> Panel:
    """Standard DevSecure360 panel with cyan border."""
    return Panel(
        content,
        title=f"[heading]{title}[/heading]" if title else None,
        subtitle=f"[secondary]{subtitle}[/secondary]" if subtitle else None,
        border_style=Style(color=border_color),
        padding=(0, 1),
    )


def make_success_panel(content, title: str = "") -> Panel:
    return make_panel(content, title=title, border_color=SUCCESS_COLOR)


def make_error_panel(content, title: str = "Error") -> Panel:
    return make_panel(content, title=title, border_color=CRITICAL_COLOR)


def make_warning_panel(content, title: str = "Warning") -> Panel:
    return make_panel(content, title=title, border_color=WARNING_COLOR)


# ─────────────────────────────────────────────
# STATUS ICONS
# ─────────────────────────────────────────────

def status_icon(ok: bool) -> str:
    return "[success]+ [/success]" if ok else "[error]x [/error]"


def severity_icon(severity: str) -> str:
    icons = {
        "Critical": "CRIT",
        "High":     "HIGH",
        "Medium":   "MED ",
        "Low":      "LOW ",
        "Info":     "INFO",
    }
    return icons.get(severity, "?   ")


# ─────────────────────────────────────────────
# ASCII LOGO
# ─────────────────────────────────────────────

LOGO_DEVSECURE = [
    r"██████╗ ███████╗██╗   ██╗███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗",
    r"██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝",
    r"██║  ██║█████╗  ██║   ██║███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ",
    r"██║  ██║██╔══╝  ╚██╗ ██╔╝╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ",
    r"██████╔╝███████╗ ╚████╔╝ ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗",
    r"╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝",
]

LOGO_360 = [
    r" ██████╗  ██████╗  ██████╗ ",
    r" ╚════██╗ ██╔════╝ ██╔══██╗",
    r"  █████╔╝ ██████╗  ██║  ██║",
    r"  ╚═══██╗ ██╔══██╗ ██║  ██║",
    r" ██████╔╝ ╚██████╔╝╚██████╔╝",
    r" ╚═════╝   ╚═════╝  ╚═════╝ ",
]

LOGO = "\n" + "\n".join(d + t for d, t in zip(LOGO_DEVSECURE, LOGO_360))

def print_logo_banner(animated: bool = True):
    """Print the dual-color DevSecure360 logo (DEVSECURE in Blue, 360 in Cyan)."""
    import time
    console.print()
    for d, t in zip(LOGO_DEVSECURE, LOGO_360):
        text = Text()
        text.append(d, style=f"bold {PRIMARY_BLUE}")
        text.append(t, style=f"bold {PRIMARY_CYAN}")
        console.print(text)
        if animated:
            time.sleep(0.06)

LOGO_SUBTITLE = "AI-Powered Application Security  •  Autonomous Security Agent"

# ─────────────────────────────────────────────
# GRADE COLORS
# ─────────────────────────────────────────────

GRADE_COLORS = {
    "A": SUCCESS_COLOR,
    "B": SUCCESS_COLOR,
    "C": WARNING_COLOR,
    "D": WARNING_COLOR,
    "F": CRITICAL_COLOR,
}

def grade_color(grade: str) -> str:
    return GRADE_COLORS.get(grade, SECONDARY)
