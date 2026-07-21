# backend/app/scanner/sast/taint/aliases.py
"""
Variable alias and taint tracking for the DevSecure360 SAST engine.

Handles taint propagation through:
    b = a                    → b aliases a, b is tainted if a is
    c = {"key": b}           → c["key"] is tainted if b is tainted
    d = c["key"]             → d is tainted if c["key"] is tainted
    e = f(a)                 → e may be tainted if a is tainted (conservative)
    query = "SELECT " + user → query is tainted if user is tainted
    query += user_input      → query becomes tainted
"""

import re


class AliasTracker:
    """
    Tracks which variables are tainted and propagates taint through assignments.

    Design decision: This is a conservative over-approximation. We prefer
    false positives (which can be reviewed) over false negatives (missed vulns).
    The sanitizer check in the taint engine reduces false positives.
    """

    def __init__(self):
        self.tainted: set[str] = set()

    def mark_tainted(self, var_name: str):
        """Mark a variable as tainted (user-controlled)."""
        self.tainted.add(var_name)

    def is_tainted(self, var_name: str) -> bool:
        """Check if a specific variable is tainted."""
        return var_name in self.tainted

    def propagate_assignment(self, target: str, value_text: str):
        """
        Given an assignment `target = value_text`, check if the right-hand
        side contains any tainted variable. If so, mark target as tainted.
        """
        if self._value_contains_taint(value_text):
            self.tainted.add(target)

    def _value_contains_taint(self, value_text: str) -> bool:
        """
        Check if a value expression contains any tainted variable name.
        Uses word-boundary regex to avoid partial matches
        (e.g., "username" should not match "name").
        """
        for var in self.tainted:
            if re.search(r'\b' + re.escape(var) + r'\b', value_text):
                return True
        return False

    def find_tainted_vars_in(self, text: str) -> list[str]:
        """Return list of all tainted variable names found in the given text."""
        found = []
        for var in self.tainted:
            if re.search(r'\b' + re.escape(var) + r'\b', text):
                found.append(var)
        return found

    def get_all_tainted(self) -> set[str]:
        """Return a copy of all currently tainted variable names."""
        return set(self.tainted)

    def __repr__(self):
        return f"AliasTracker(tainted={sorted(self.tainted)})"
