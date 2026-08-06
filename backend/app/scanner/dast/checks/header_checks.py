"""
DevSecure360 — DAST Security Header Checks
==========================================
Passive security posture analysis via HTTP response headers.
Enterprise-grade checks matching OWASP WSTG-CONF-07, Mozilla Observatory,
SecurityHeaders.com criteria.
"""

import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class HeaderFinding:
    issue: str
    description: str
    remediation: str
    severity: str       # "Low" | "Medium" | "High"
    confidence: str
    owasp: str
    cwe: str
    cvss_score: float


def check_security_headers(response_headers: dict, url: str, cookies: list = None) -> list[HeaderFinding]:
    """
    Full enterprise-grade security header audit.
    Returns a list of HeaderFinding objects for each issue found.
    """
    findings = []
    headers_lower = {k.lower(): v for k, v in response_headers.items()}
    cookies = cookies or []

    # 1. Strict-Transport-Security (HSTS)
    hsts = headers_lower.get("strict-transport-security", "")
    if not hsts:
        findings.append(HeaderFinding(
            issue="Missing HTTP Strict-Transport-Security (HSTS) Header",
            description=(
                "The server does not include the Strict-Transport-Security header. "
                "This allows attackers to perform protocol downgrade attacks and intercept HTTPS traffic via MITM."
            ),
            remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            severity="Medium",
            confidence="Confirmed",
            owasp="A02:2021",
            cwe="CWE-319",
            cvss_score=5.9,
        ))
    else:
        if "max-age" in hsts:
            max_age_str = [p.strip() for p in hsts.split(";") if "max-age" in p.lower()]
            if max_age_str:
                try:
                    max_age = int(max_age_str[0].split("=")[1].strip())
                    if max_age < 15768000:  # 6 months
                        findings.append(HeaderFinding(
                            issue="HSTS max-age Too Short",
                            description=f"HSTS max-age is set to {max_age}s (< 6 months). Browsers won't cache the rule long enough.",
                            remediation="Set max-age to at least 31536000 (1 year).",
                            severity="Low",
                            confidence="Confirmed",
                            owasp="A02:2021",
                            cwe="CWE-319",
                            cvss_score=3.1,
                        ))
                except (ValueError, IndexError):
                    pass
        if "includesubdomains" not in hsts.lower():
            findings.append(HeaderFinding(
                issue="HSTS Missing includeSubDomains",
                description="HSTS does not include the includeSubDomains directive. Subdomains remain unprotected.",
                remediation="Add 'includeSubDomains' to the HSTS header.",
                severity="Low",
                confidence="Confirmed",
                owasp="A02:2021",
                cwe="CWE-319",
                cvss_score=3.1,
            ))

    # 2. Content-Security-Policy (CSP)
    csp = headers_lower.get("content-security-policy", "")
    if not csp:
        findings.append(HeaderFinding(
            issue="Missing Content-Security-Policy (CSP) Header",
            description=(
                "No CSP header found. Without CSP, the browser will execute inline scripts "
                "and load resources from any origin, enabling XSS attacks."
            ),
            remediation=(
                "Implement a strict CSP. At minimum: "
                "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"
            ),
            severity="Medium",
            confidence="Confirmed",
            owasp="A03:2021",
            cwe="CWE-1021",
            cvss_score=6.1,
        ))
    else:
        if "unsafe-inline" in csp:
            findings.append(HeaderFinding(
                issue="CSP Allows 'unsafe-inline' Scripts",
                description="The CSP includes 'unsafe-inline' for scripts, defeating protection against XSS.",
                remediation="Remove 'unsafe-inline'. Use nonces or hashes for inline scripts.",
                severity="Medium",
                confidence="Confirmed",
                owasp="A03:2021",
                cwe="CWE-1021",
                cvss_score=6.1,
            ))
        if "unsafe-eval" in csp:
            findings.append(HeaderFinding(
                issue="CSP Allows 'unsafe-eval'",
                description="The CSP includes 'unsafe-eval', allowing execution of dynamic code via eval().",
                remediation="Remove 'unsafe-eval'. Refactor code to avoid eval(), Function(), setTimeout with strings.",
                severity="Medium",
                confidence="Confirmed",
                owasp="A03:2021",
                cwe="CWE-1021",
                cvss_score=5.4,
            ))
        if "default-src *" in csp or "default-src 'none'" not in csp and "script-src" not in csp:
            findings.append(HeaderFinding(
                issue="Overly Permissive CSP (Wildcard Source)",
                description="CSP uses a wildcard (*) or lacks a specific script-src directive. Allows scripts from any origin.",
                remediation="Use specific host whitelists instead of wildcards. Define both default-src and script-src.",
                severity="Low",
                confidence="Probable",
                owasp="A03:2021",
                cwe="CWE-1021",
                cvss_score=4.3,
            ))

    # 3. X-Frame-Options / frame-ancestors in CSP
    xfo = headers_lower.get("x-frame-options", "")
    csp_frame = "frame-ancestors" in csp.lower() if csp else False
    if not xfo and not csp_frame:
        findings.append(HeaderFinding(
            issue="Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
            description=(
                "The server does not prevent its content from being embedded in iframes. "
                "This makes the site vulnerable to UI redressing / clickjacking attacks."
            ),
            remediation=(
                "Add X-Frame-Options: DENY or SAMEORIGIN, or add "
                "'frame-ancestors 'none'' to your CSP."
            ),
            severity="Medium",
            confidence="Confirmed",
            owasp="A04:2021",
            cwe="CWE-1021",
            cvss_score=4.3,
        ))
    elif xfo.upper() not in ("DENY", "SAMEORIGIN") and not csp_frame:
        findings.append(HeaderFinding(
            issue="Misconfigured X-Frame-Options",
            description=f"X-Frame-Options is set to '{xfo}' which is not a recognized value (DENY or SAMEORIGIN).",
            remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
            severity="Low",
            confidence="Confirmed",
            owasp="A04:2021",
            cwe="CWE-1021",
            cvss_score=3.1,
        ))

    # 4. X-Content-Type-Options
    xcto = headers_lower.get("x-content-type-options", "")
    if "nosniff" not in xcto.lower():
        findings.append(HeaderFinding(
            issue="Missing X-Content-Type-Options: nosniff",
            description=(
                "The X-Content-Type-Options header is not set to 'nosniff'. "
                "Browsers may MIME-sniff the content type, allowing attackers to serve malicious "
                "scripts with an innocent MIME type."
            ),
            remediation="Add: X-Content-Type-Options: nosniff",
            severity="Low",
            confidence="Confirmed",
            owasp="A04:2021",
            cwe="CWE-693",
            cvss_score=3.7,
        ))

    # 5. Referrer-Policy
    rp = headers_lower.get("referrer-policy", "")
    if not rp:
        findings.append(HeaderFinding(
            issue="Missing Referrer-Policy Header",
            description=(
                "No Referrer-Policy header found. Browsers will send the full Referer header "
                "with cross-origin requests, potentially leaking sensitive URLs, tokens, or session IDs."
            ),
            remediation="Add: Referrer-Policy: strict-origin-when-cross-origin",
            severity="Low",
            confidence="Confirmed",
            owasp="A01:2021",
            cwe="CWE-200",
            cvss_score=3.1,
        ))
    elif rp.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        findings.append(HeaderFinding(
            issue="Permissive Referrer-Policy",
            description=f"Referrer-Policy is set to '{rp}', which leaks full URLs to third parties.",
            remediation="Use: Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
            severity="Low",
            confidence="Confirmed",
            owasp="A01:2021",
            cwe="CWE-200",
            cvss_score=3.1,
        ))

    # 6. Permissions-Policy
    if not headers_lower.get("permissions-policy", "") and not headers_lower.get("feature-policy", ""):
        findings.append(HeaderFinding(
            issue="Missing Permissions-Policy Header",
            description=(
                "No Permissions-Policy header found. Browsers may grant powerful APIs "
                "(camera, microphone, geolocation) to embedded third-party content."
            ),
            remediation="Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            severity="Low",
            confidence="Confirmed",
            owasp="A04:2021",
            cwe="CWE-693",
            cvss_score=3.1,
        ))

    # 7. Server banner disclosure
    server = headers_lower.get("server", "")
    x_powered = headers_lower.get("x-powered-by", "")
    if server and any(keyword in server.lower() for keyword in ["apache", "nginx", "iis", "tomcat", "lighttpd"]):
        findings.append(HeaderFinding(
            issue=f"Server Technology Disclosure via 'Server' Header: {server}",
            description=(
                f"The server exposes its technology and version in the 'Server' header: '{server}'. "
                "Attackers use this for targeted vulnerability research."
            ),
            remediation="Configure the web server to suppress or obscure the Server header.",
            severity="Low",
            confidence="Confirmed",
            owasp="A05:2021",
            cwe="CWE-200",
            cvss_score=3.1,
        ))
    if x_powered:
        findings.append(HeaderFinding(
            issue=f"Technology Disclosure via 'X-Powered-By' Header: {x_powered}",
            description=(
                f"The server exposes framework/runtime info via 'X-Powered-By: {x_powered}'. "
                "This helps attackers identify known CVEs for the disclosed technology."
            ),
            remediation="Disable the X-Powered-By header (e.g., in Express: app.disable('x-powered-by')).",
            severity="Low",
            confidence="Confirmed",
            owasp="A05:2021",
            cwe="CWE-200",
            cvss_score=3.1,
        ))

    # 8. Cache-Control on responses containing potential sensitive data
    cache = headers_lower.get("cache-control", "")
    pragma = headers_lower.get("pragma", "")
    if not cache or ("no-store" not in cache and "private" not in cache):
        findings.append(HeaderFinding(
            issue="Missing Cache-Control: no-store for Sensitive Responses",
            description=(
                "Responses may be cached by proxies/browsers without Cache-Control: no-store. "
                "Sensitive pages (login, profile, dashboard) should never be cached."
            ),
            remediation="For authenticated / sensitive pages, add: Cache-Control: no-store, no-cache, must-revalidate",
            severity="Low",
            confidence="Probable",
            owasp="A04:2021",
            cwe="CWE-524",
            cvss_score=3.1,
        ))

    # 9. Cookie security flags
    for cookie in cookies:
        name = cookie.get("name", "unknown")
        if not cookie.get("httpOnly", False):
            findings.append(HeaderFinding(
                issue=f"Cookie '{name}' Missing HttpOnly Flag",
                description=(
                    f"The '{name}' cookie does not have the HttpOnly flag set. "
                    "JavaScript can read this cookie, enabling session theft via XSS."
                ),
                remediation=f"Set the HttpOnly attribute on the '{name}' cookie.",
                severity="Medium",
                confidence="Confirmed",
                owasp="A05:2021",
                cwe="CWE-1004",
                cvss_score=5.4,
            ))
        if not cookie.get("secure", False):
            findings.append(HeaderFinding(
                issue=f"Cookie '{name}' Missing Secure Flag",
                description=(
                    f"The '{name}' cookie does not have the Secure flag set. "
                    "The cookie will be transmitted over unencrypted HTTP connections."
                ),
                remediation=f"Set the Secure attribute on the '{name}' cookie.",
                severity="Medium",
                confidence="Confirmed",
                owasp="A02:2021",
                cwe="CWE-614",
                cvss_score=5.4,
            ))
        samesite = (cookie.get("sameSite") or "").lower()
        if samesite not in ("strict", "lax"):
            findings.append(HeaderFinding(
                issue=f"Cookie '{name}' Missing or Weak SameSite Attribute",
                description=(
                    f"The '{name}' cookie has SameSite={samesite or 'None'}. "
                    "Without SameSite=Strict or Lax, the cookie is sent with cross-site requests, enabling CSRF."
                ),
                remediation=f"Set SameSite=Strict or SameSite=Lax on the '{name}' cookie.",
                severity="Medium",
                confidence="Confirmed",
                owasp="A01:2021",
                cwe="CWE-352",
                cvss_score=4.3,
            ))

    return findings
