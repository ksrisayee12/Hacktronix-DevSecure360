"""
DevSecure360 — Shared Type Contract
=====================================
This is the single source of truth for all data structures in the platform.

Rules:
- NEVER redefine Finding, ScanResult, Severity, TaintStep, ScanType, ScanStatus anywhere else.
- NEVER return raw dicts from scan engines. Always return ScanResult.
- If a new field is needed, add it here and update all modules.
- Every scan engine (SAST, DAST, Port, Secrets) returns ScanResult.
- The platform (main.py) only deals with ScanResult objects.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"


class ScanType(str, Enum):
    SAST       = "sast"
    DAST       = "dast"
    PORT       = "port"
    SECRET     = "secret"
    DEPENDENCY = "dependency"


class ScanStatus(str, Enum):
    QUEUED    = "queued"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"


@dataclass
class TaintStep:
    """
    One step in the taint trace from source to sink.
    Used by the SAST engine to show the exact path
    a vulnerability travels through the code.

    Example:
        step=1  line=38  "Source: request.args.get('name') → user is TAINTED"
        step=2  line=40  "Taint propagates via string concat → query is TAINTED"
        step=3  line=42  "Sink: db.execute(query) called with TAINTED data"
    """
    step: int
    line: int
    file: str
    description: str


@dataclass(kw_only=True)
class Finding:
    """
    A unified, enterprise-grade finding object covering SAST, DAST, and Port scanning.
    SAST findings:  have file, line, taint_trace. url is None.
    DAST findings:  have url, evidence (HTTP request/response). file/line are None.
    Port findings:  have url (host:port). file/line/taint_trace are empty.
    Secret findings: have file, line. url is None.
    """

    # Identity
    id: str                             # UUID — unique per finding
    rule_id: str                        # e.g. "python_sqli_001"
    vuln_class: str                     # "SQLi", "XSS", "CMDi", "SSRF", "Open Port", etc.
    scan_type: ScanType

    # Location — one or the other, not both
    file: Optional[str]                 # SAST/Secret: relative file path
    line: Optional[int]                 # SAST/Secret: line number
    url: Optional[str]                  # DAST/Port: endpoint URL or host:port

    # Classification
    severity: Severity
    confidence: str                     # "Confirmed" / "Probable" / "Tentative"
    cwe: Optional[str] = None                  # "CWE-89", "CWE-79", "CWE-78", etc.
    owasp: Optional[str] = None               # "A03:2021", "A07:2021", etc.

    # Human-readable content
    issue: str                          # Short title: "SQL Injection via unsanitized input"
    description: str                    # Full explanation of the vulnerability
    evidence: Optional[str]             # SAST: code snippet. DAST: HTTP req/res.
    taint_trace: list                   # list[TaintStep] — SAST only, empty list for others
    remediation: str                    # Specific fix guidance

    # Meta
    tool: str                           # "devsecure_sast" / "devsecure_dast" / "devsecure_port" / "devsecure_secrets"
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None


@dataclass
class ScanResult:
    """
    The return type of every scan engine.
    main.py only ever handles ScanResult objects.

    Usage:
        engine = SASTEngine()
        result: ScanResult = engine.scan(target_path="/path/to/code")

        engine = DASTEngine()
        result: ScanResult = engine.scan(target_url="https://example.com")
    """
    scan_id: str                        # UUID — unique per scan job
    scan_type: ScanType
    status: ScanStatus
    target: str                         # File path (SAST) or URL (DAST) or host (Port)
    findings: list                      # list[Finding]
    score: Optional[dict]               # {"score": 42, "grade": "F", "counts": {...}, "max_cvss": 9.8}
    started_at: str                     # ISO 8601 datetime string
    completed_at: Optional[str]         # ISO 8601 datetime string — None if still running
    error: Optional[str]                # Error message if status == FAILED
