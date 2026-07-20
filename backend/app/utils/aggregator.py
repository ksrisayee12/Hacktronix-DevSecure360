"""
DevSecure360 — CVSS-Based Scoring Engine
==========================================
Replaces the old weight-based scoring formula which was mathematically flawed.

Old formula: score = 100 - (total_weight / max_possible) * 100
Problem:     100 Low findings scored 66. 1 Critical RCE scored similar. Meaningless.

New formula: score = 100 - (highest_cvss_score * 10)
Logic:       One Critical RCE (CVSS 9.8) tanks score to 2. That's correct.
             10 Low findings (CVSS 2.0) score 80. Also correct.
"""

from datetime import datetime

# CVSS v3.1 base scores per vulnerability class
CVSS_SCORES = {
    "SQLi":              9.8,
    "NoSQLi":            8.8,
    "CMDi":              9.8,
    "RCE":               10.0,
    "eval":              9.8,
    "XSS":               6.1,
    "SSRF":              8.6,
    "Path Traversal":    7.5,
    "LFI":               7.5,
    "SSTI":              9.8,
    "Deserialization":   9.8,
    "XXE":               7.5,
    "Hardcoded Secret":  7.5,
    "Weak Crypto":       5.9,
    "Open Redirect":     6.1,
    "CORS":              5.4,
    "Auth Bypass":       8.8,
    "IDOR":              6.5,
    "Open Port":         2.0,
    "Default":           5.0,
}

SEVERITY_CVSS_FALLBACK = {
    "Critical": 9.5,
    "High":     7.5,
    "Medium":   5.0,
    "Low":      2.0,
    "Info":     0.5,
}


def compute_score(findings: list) -> dict:
    """
    Compute security score from a list of findings.
    Accepts both Finding dataclass objects and plain dicts.

    Returns:
        {
            "score": int (0-100),
            "grade": str ("A"/"B"/"C"/"D"/"F"),
            "counts": {"Critical": N, "High": N, "Medium": N, "Low": N, "Info": N},
            "max_cvss": float,
            "calculated_at": str (ISO datetime)
        }
    """
    if not findings:
        return {
            "score": 100,
            "grade": "A",
            "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "max_cvss": 0.0,
            "calculated_at": datetime.utcnow().isoformat()
        }

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    max_cvss = 0.0

    for f in findings:
        # Support both dataclass and dict
        if isinstance(f, dict):
            vuln_class = f.get("vuln_class", "Default")
            severity   = f.get("severity", "Medium")
        else:
            vuln_class = getattr(f, "vuln_class", "Default")
            sev = getattr(f, "severity", "Medium")
            severity = sev.value if hasattr(sev, "value") else sev

        # Count by severity
        if severity in counts:
            counts[severity] += 1

        # Get CVSS score — try by vuln class first, fall back to severity
        cvss = CVSS_SCORES.get(vuln_class, SEVERITY_CVSS_FALLBACK.get(severity, 5.0))
        if cvss > max_cvss:
            max_cvss = cvss

    # Score = 100 minus impact of worst finding
    # max_cvss 10.0 → score 0 | max_cvss 5.0 → score 50 | max_cvss 0 → score 100
    raw_score = max(0, 100 - int(max_cvss * 10))

    # Grade
    if raw_score >= 90:   grade = "A"
    elif raw_score >= 75: grade = "B"
    elif raw_score >= 60: grade = "C"
    elif raw_score >= 40: grade = "D"
    else:                 grade = "F"

    return {
        "score": raw_score,
        "grade": grade,
        "counts": counts,
        "max_cvss": round(max_cvss, 1),
        "calculated_at": datetime.utcnow().isoformat()
    }
