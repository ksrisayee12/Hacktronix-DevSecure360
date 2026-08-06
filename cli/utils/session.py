"""
DevSecure360 CLI — Session State
==================================
Holds in-memory state shared across interactive commands within one CLI session.
Stateless commands (one-shot CLI invocations) create a fresh session per run.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Any
import os


@dataclass
class CLISession:
    """
    Singleton-style session object passed between CLI commands.
    Stores last scan result, findings, and workspace context.
    """
    # Workspace
    workspace_path: str = field(default_factory=lambda: os.getcwd())
    project_name: str = "DevSecure360"

    # Scan state
    last_scan_result: Optional[Any] = None     # ScanResult from engine_bridge
    findings: List[Any] = field(default_factory=list)   # list[Finding]
    scan_target: Optional[str] = None

    # Remediation state
    remediation_plan: List[dict] = field(default_factory=list)
    patched_files: dict = field(default_factory=dict)    # {rel_path: patched_content}
    original_files: dict = field(default_factory=dict)   # {rel_path: original_content}

    # Score
    score: Optional[dict] = None

    # Flags
    scan_ran: bool = False
    remediation_applied: bool = False

    def reset(self):
        """Clear scan and remediation state for a fresh run."""
        self.last_scan_result = None
        self.findings = []
        self.scan_target = None
        self.remediation_plan = []
        self.patched_files = {}
        self.original_files = {}
        self.score = None
        self.scan_ran = False
        self.remediation_applied = False

    def has_findings(self) -> bool:
        return bool(self.findings)

    def get_findings_by_severity(self, severity: str) -> list:
        """Filter findings by severity name (Critical, High, Medium, Low, Info)."""
        result = []
        for f in self.findings:
            if isinstance(f, dict):
                sev = f.get("severity", "")
            else:
                sev = getattr(f, "severity", "")
                if hasattr(sev, "value"):
                    sev = sev.value
            if sev.lower() == severity.lower():
                result.append(f)
        return result

    def get_finding_by_id(self, finding_id: str) -> Optional[Any]:
        """Look up a finding by UUID or 1-based index (as string)."""
        # Try numeric index first
        if finding_id.isdigit():
            idx = int(finding_id) - 1
            if 0 <= idx < len(self.findings):
                return self.findings[idx]

        # Try UUID match
        for f in self.findings:
            fid = f.get("id") if isinstance(f, dict) else getattr(f, "id", None)
            if fid and fid.startswith(finding_id):
                return f
        return None


# Module-level singleton for interactive sessions
_session = CLISession()


def get_session() -> CLISession:
    """Returns the current CLI session singleton."""
    return _session


def reset_session():
    """Resets the current CLI session."""
    _session.reset()
