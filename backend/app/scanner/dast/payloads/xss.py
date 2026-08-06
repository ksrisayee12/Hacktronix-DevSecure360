"""
DevSecure360 — DAST XSS Payloads
====================================
Cross-Site Scripting payload set for reflected and stored XSS detection.
Sources: OWASP XSS Filter Evasion Cheat Sheet, PortSwigger XSS corpus.
"""


def get_reflected_payloads(canary_id: str) -> list:
    """
    Context-aware XSS payloads. The canary_id is embedded so the oracle
    can distinguish our execution from pre-existing page scripts.
    """
    return [
        # HTML body context
        f"<script>window.__xss_{canary_id}=1</script>",
        f"<img src=x onerror=\"window.__xss_{canary_id}=1\">",
        f"<svg onload=\"window.__xss_{canary_id}=1\">",

        # Attribute context (closes the attribute then injects event handler)
        f"\" onmouseover=\"window.__xss_{canary_id}=1\" data-x=\"",
        f"' onmouseover='window.__xss_{canary_id}=1' x='",

        # JavaScript string break-out context
        f"';window.__xss_{canary_id}=1;//",
        f'";window.__xss_{canary_id}=1;//',

        # Filter evasion
        f"<ScRiPt>window.__xss_{canary_id}=1</ScRiPt>",
        f"<img src=\"x\" onerror=\"window.__xss_{canary_id}=1\">",

        # HTML entities
        f"&lt;script&gt;window.__xss_{canary_id}=1&lt;/script&gt;",

        # URL encoding bypass
        f"%3Cscript%3Ewindow.__xss_{canary_id}=1%3C%2Fscript%3E",
    ]


def get_stored_check_payload(canary_id: str) -> str:
    """Payload to plant for stored XSS — look for it in subsequent GET requests."""
    return f"<script>window.__xss_{canary_id}=1</script>"


def xss_canary_marker(canary_id: str) -> str:
    """The JS variable name set when XSS fires — used by the headless oracle."""
    return f"__xss_{canary_id}"
