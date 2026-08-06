"""
DevSecure360 CLI — Engine Bridge
==================================
Thin adapter between the CLI layer and the existing backend engines.
ALL actual scanning/remediation logic lives in the backend modules.
This file ONLY delegates — it never duplicates logic.

Engines used (exactly as main.py uses them):
  - SASTEngine           → backend/app/scanner/sast/engine.py
  - RemediationEngine    → backend/app/scanner/remediation_engine.py
  - compute_score        → backend/app/utils/aggregator.py
  - get_scan_history     → backend/app/database/history_db.py
  - save_scan_result     → backend/app/database/history_db.py
"""

from __future__ import annotations
import os
import sys

# ── Ensure the backend package is on the Python path ──────────────────────────
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_BACKEND   = os.path.join(_REPO_ROOT, "backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


# ── Lazy imports (defer heavy engine init until first call) ────────────────────
def _sast_engine():
    from app.scanner.sast.engine import SASTEngine
    return SASTEngine()


def _remediation_engine():
    from app.scanner.remediation_engine import RemediationEngine
    return RemediationEngine


def _compute_score():
    from app.utils.aggregator import compute_score
    return compute_score


def _history():
    from app.database.history_db import get_scan_history, save_scan_result
    return get_scan_history, save_scan_result


# ── Public API ─────────────────────────────────────────────────────────────────

def run_sast(target_path: str):
    """
    Run the SAST engine on a file or directory.
    Returns a ScanResult object (same type as main.py returns).
    """
    engine = _sast_engine()
    result = engine.scan(target_path=target_path)
    # Persist to scan history (same as main.py does)
    _, save = _history()
    save("sast", {
        "findings": [_finding_to_dict(f) for f in result.findings],
        "score": result.score
    })
    return result


def run_remediation(finding, file_content: str = None) -> str:
    """
    Generate an AI fix for a single finding.
    Delegates to RemediationEngine.generate_fix() — no logic added.
    """
    RemediationEngine = _remediation_engine()
    return RemediationEngine.generate_fix(finding, file_content)


def compute_security_score(findings: list) -> dict:
    """
    Compute CVSS-based security score from a findings list.
    Delegates to the existing aggregator.
    """
    score_fn = _compute_score()
    return score_fn(findings)


def get_history(limit: int = None) -> list:
    """Return scan history from the history DB."""
    get_fn, _ = _history()
    return get_fn(limit)


def check_backend_health() -> dict:
    """
    Verify that the backend modules can be imported and instantiated.
    Used by `devsecure doctor`.
    Returns a dict of {component: ok_bool}.
    """
    results = {}

    try:
        from app.scanner.sast.engine import SASTEngine
        SASTEngine()
        results["SAST Engine"] = True
    except Exception as e:
        results["SAST Engine"] = False

    try:
        from app.scanner.remediation_engine import RemediationEngine
        results["Remediation Engine"] = True
    except Exception as e:
        results["Remediation Engine"] = False

    try:
        from app.utils.aggregator import compute_score
        results["Score Aggregator"] = True
    except Exception as e:
        results["Score Aggregator"] = False

    try:
        from app.database.history_db import get_scan_history
        get_scan_history(limit=1)
        results["History DB"] = True
    except Exception as e:
        results["History DB"] = False

    try:
        import requests
        base_url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
        r = requests.get(f"{base_url}/api/tags", timeout=3)
        results["Ollama AI"] = r.status_code == 200
    except Exception:
        results["Ollama AI"] = False

    return results


def check_api_health() -> bool:
    """Check if the FastAPI backend is running (for dashboard command)."""
    try:
        import requests
        r = requests.get("http://localhost:8000/", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


# ── Helper ─────────────────────────────────────────────────────────────────────

def _finding_to_dict(f) -> dict:
    """Convert Finding dataclass to JSON-serializable dict (mirrors main.py _f())."""
    if isinstance(f, dict):
        return f
    return {
        "id":          f.id,
        "rule_id":     f.rule_id,
        "vuln_class":  f.vuln_class,
        "scan_type":   f.scan_type.value if hasattr(f.scan_type, "value") else f.scan_type,
        "file":        f.file,
        "line":        f.line,
        "url":         f.url,
        "severity":    f.severity.value if hasattr(f.severity, "value") else f.severity,
        "confidence":  f.confidence,
        "cwe":         f.cwe,
        "owasp":       f.owasp,
        "issue":       f.issue,
        "description": f.description,
        "evidence":    f.evidence,
        "taint_trace": [
            {"step": t.step, "line": t.line, "file": t.file, "description": t.description}
            if not isinstance(t, dict) else t
            for t in (f.taint_trace or [])
        ],
        "remediation": f.remediation,
        "tool":        f.tool,
        "cvss_score":  getattr(f, "cvss_score", None),
    }


def findings_to_dicts(findings: list) -> list[dict]:
    """Convert a list of Finding objects or dicts to plain dicts."""
    return [_finding_to_dict(f) for f in findings]


def get_field(finding, field: str, default=None):
    """Safely get a field from a Finding object or dict."""
    if isinstance(finding, dict):
        val = finding.get(field, default)
    else:
        val = getattr(finding, field, default)
    if hasattr(val, "value"):
        return val.value
    return val
