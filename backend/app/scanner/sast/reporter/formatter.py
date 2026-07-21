# backend/app/scanner/sast/reporter/formatter.py
"""
Finding formatter for the DevSecure360 SAST engine.

Converts TaintFinding objects (raw analysis output) into Finding dataclass objects
with full taint traces, CWE mappings, and code evidence.

Also handles the hardcoded secrets pattern rule (no taint trace needed).
"""

import uuid
import re
from app.shared.types import Finding, TaintStep, Severity, ScanType
from ..taint.engine import TaintFinding

SEVERITY_MAP = {
    "Critical": Severity.CRITICAL,
    "High":     Severity.HIGH,
    "Medium":   Severity.MEDIUM,
    "Low":      Severity.LOW,
    "Info":     Severity.INFO,
}

# Standardized SAST CVSS v3.1 mappings per vulnerability class
CVSS_MAPPINGS = {
    "SQLi": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "CMDi": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "Code Injection": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "Deserialization": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "Insecure Deserialization": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "Path Traversal": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "SSRF": {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
    "XXE": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "XSS": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "DOM XSS": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "Open Redirect": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "SSTI": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "Mass Assignment": {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"},
    "ReDoS": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
    "Hardcoded Secret": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "Prototype Pollution": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "Buffer Overflow": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
}


def taint_finding_to_finding(
    taint_finding: TaintFinding,
    rule: dict,
    file_path: str,
    source_bytes: bytes
) -> Finding:
    """Convert a TaintFinding into a Finding dataclass with full taint trace."""

    # Build taint trace
    taint_trace = []
    for i, step in enumerate(taint_finding.taint_path):
        taint_trace.append(TaintStep(
            step=i + 1,
            line=step["line"],
            file=file_path,
            description=step["description"]
        ))

    # Extract code snippet around the sink line
    evidence = _extract_snippet(source_bytes, taint_finding.sink_line)

    severity = SEVERITY_MAP.get(rule.get("severity", "Medium"), Severity.MEDIUM)
    cvss = CVSS_MAPPINGS.get(taint_finding.vuln_class, {"score": None, "vector": None})

    return Finding(
        id=str(uuid.uuid4()),
        rule_id=taint_finding.rule_id,
        vuln_class=taint_finding.vuln_class,
        scan_type=ScanType.SAST,
        file=file_path,
        line=taint_finding.sink_line,
        url=None,
        severity=severity,
        confidence=rule.get("confidence", "Confirmed"),
        cwe=rule.get("cwe"),
        owasp=rule.get("owasp"),
        cvss_score=cvss["score"],
        cvss_vector=cvss["vector"],
        issue=rule.get("issue", f"{taint_finding.vuln_class} vulnerability detected"),
        description=rule.get("message", ""),
        evidence=evidence,
        taint_trace=taint_trace,
        remediation=rule.get("remediation", ""),
        tool="devsecure_sast"
    )


def secret_finding(
    file_path: str,
    line: int,
    var_name: str,
    value_snippet: str,
    rule: dict
) -> Finding:
    """Create a Finding for a hardcoded secret detected by pattern matching."""
    if len(value_snippet) > 40:
        evidence_val = f'{var_name} = "{value_snippet[:40]}..."'
    else:
        evidence_val = f'{var_name} = "{value_snippet}"'

    cvss = CVSS_MAPPINGS.get("Hardcoded Secret", {"score": None, "vector": None})

    return Finding(
        id=str(uuid.uuid4()),
        rule_id=rule.get("rule_id", "secret_001"),
        vuln_class="Hardcoded Secret",
        scan_type=ScanType.SAST,
        file=file_path,
        line=line,
        url=None,
        severity=Severity.HIGH,
        confidence="Confirmed",
        cwe=rule.get("cwe", "CWE-798"),
        owasp=rule.get("owasp", "A07:2021"),
        cvss_score=cvss["score"],
        cvss_vector=cvss["vector"],
        issue=rule.get("issue", "Hardcoded secret in source code"),
        description=rule.get("message", ""),
        evidence=evidence_val,
        taint_trace=[],
        remediation=rule.get("remediation", "Use environment variables instead of hardcoded secrets."),
        tool="devsecure_sast"
    )


def _extract_snippet(source_bytes: bytes, line_number: int, context: int = 1) -> str:
    """Extract source code lines around a given line number with context."""
    try:
        lines = source_bytes.decode("utf-8", errors="replace").splitlines()
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        snippet_lines = []
        for i in range(start, end):
            prefix = "→ " if i == line_number - 1 else "  "
            snippet_lines.append(f"{prefix}{i + 1}: {lines[i]}")
        return "\n".join(snippet_lines)
    except Exception:
        return ""
