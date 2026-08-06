"""
DevSecure360 CLI — NLP Command Router
========================================
Lightweight keyword-based natural language router for the interactive shell.
Maps free-text phrases to CLI command functions — no LLM required.

Examples:
  "scan my project"          → scan(".")
  "scan backend"             → scan("backend/")
  "show critical"            → explain("critical")
  "remediation plan"         → remediation_plan()
  "generate report"          → report()
  "open dashboard"           → dashboard()
"""

from __future__ import annotations
import re
import os
from typing import Optional, Callable, Tuple


# ─────────────────────────────────────────────
# RULE TABLE
# Each entry: (pattern, handler_key, arg_extractor)
# ─────────────────────────────────────────────

_RULES: list[Tuple[re.Pattern, str, Optional[Callable]]] = []


def _rule(pattern: str, handler: str, arg: Optional[Callable] = None):
    _RULES.append((re.compile(pattern, re.IGNORECASE), handler, arg))


# Scan variants
_rule(r"^scan\s+(.+)$",                          "scan",        lambda m: m.group(1).strip())
_rule(r"scan (my )?project",                      "scan",        lambda m: ".")
_rule(r"scan (the )?backend",                     "scan",        lambda m: "backend")
_rule(r"scan (the )?frontend",                    "scan",        lambda m: "frontend")
_rule(r"scan dependencies",                       "deps",        None)
_rule(r"scan (website|url|site)\s+(https?://\S+)", "dast",       lambda m: m.group(2))
_rule(r"scan\s+(https?://\S+)",                   "dast",        lambda m: m.group(1))
_rule(r"^scan$",                                  "scan",        lambda m: ".")
_rule(r"find secrets",                            "secrets",     None)
_rule(r"scan (for )?secrets",                     "secrets",     None)
_rule(r"(secure|analyze|audit) (my |the )?app(lication)?", "scan", lambda m: ".")
_rule(r"full scan",                               "scan",        lambda m: ".")

# Explain / show variants
_rule(r"show (all )?findings?",                   "explain",     None)
_rule(r"show (all )?critical",                    "explain",     lambda m: "critical")
_rule(r"show (all )?high",                        "explain",     lambda m: "high")
_rule(r"show (all )?medium",                      "explain",     lambda m: "medium")
_rule(r"show (all )?low",                         "explain",     lambda m: "low")
_rule(r"explain (\d+)",                           "explain",     lambda m: m.group(1))
_rule(r"explain critical",                        "explain",     lambda m: "critical")
_rule(r"explain high",                            "explain",     lambda m: "high")
_rule(r"explain medium",                          "explain",     lambda m: "medium")
_rule(r"explain low",                             "explain",     lambda m: "low")
_rule(r"explain (.+)",                            "explain",     lambda m: m.group(1).strip())
_rule(r"^explain$",                               "explain",     None)

# Remediation variants
_rule(r"^fix$",                                   "remediation_plan",      None)
_rule(r"^plan$",                                  "remediation_plan",      None)
_rule(r"^preview$",                               "remediation_preview",   None)
_rule(r"^apply$",                                 "remediation_apply",     None)
_rule(r"(generate |create )?(a )?(remediation )?fix", "remediation_plan", None)
_rule(r"(generate |create )?(a )?remediation plan", "remediation_plan",    None)
_rule(r"preview (remediation|fix(es)?|patch(es)?)", "remediation_preview", None)
_rule(r"(apply|run) (remediation|fix(es)?|patch(es)?)", "remediation_apply", None)
_rule(r"rollback",                                "remediation_rollback",  None)
_rule(r"^remediation plan$",                      "remediation_plan",      None)
_rule(r"^remediation preview$",                   "remediation_preview",   None)
_rule(r"^remediation apply$",                     "remediation_apply",     None)

# Validate
_rule(r"^validate$",                              "validate",    None)
_rule(r"validate (fixes?|patches?|remediation)",  "validate",    None)

# Reports
_rule(r"report json",                             "report_json", None)
_rule(r"report html",                             "report_html", None)
_rule(r"report pdf",                              "report_pdf",  None)
_rule(r"export (findings?|report|csv)",           "export",      None)
_rule(r"(generate |create )?(a )?report",         "report",      None)

# Dashboard
_rule(r"(open |show )?(the )?dashboard",          "dashboard",   None)

# Project commands
_rule(r"^status$",                                "status",      None)
_rule(r"(show |check )?status",                   "status",      None)
_rule(r"^doctor$",                                "doctor",      None)
_rule(r"(health|doctor) check",                   "doctor",      None)
_rule(r"^version$",                               "version",     None)
_rule(r"^init$",                                  "init",        None)

# Watch / diff
_rule(r"^watch$",                                 "watch",       None)
_rule(r"watch (.+)",                              "watch",       lambda m: m.group(1).strip())
_rule(r"^diff$",                                  "diff",        None)

# Help
_rule(r"^help$",                                  "help",        None)
_rule(r"^(quit|exit|bye)$",                       "exit",        None)
_rule(r"^clear$",                                 "clear",       None)


# ─────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────

class RouteResult:
    def __init__(self, handler: str, arg: Optional[str] = None):
        self.handler = handler
        self.arg     = arg

    def __repr__(self):
        return f"RouteResult(handler={self.handler!r}, arg={self.arg!r})"


def route(text: str) -> Optional[RouteResult]:
    """
    Match a natural-language string to a CLI handler.
    Returns RouteResult or None if no match.
    """
    text = text.strip()
    if not text:
        return None

    for pattern, handler, arg_extractor in _RULES:
        match = pattern.search(text)
        if match:
            arg = None
            if arg_extractor:
                try:
                    arg = arg_extractor(match)
                except Exception:
                    arg = None
            return RouteResult(handler=handler, arg=arg)

    return None


def is_exit(text: str) -> bool:
    """Returns True if the text is a quit/exit command."""
    return bool(re.match(r"^(quit|exit|bye|q)$", text.strip(), re.IGNORECASE))
