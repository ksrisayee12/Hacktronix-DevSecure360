"""
DevSecure360 — DAST HTTP Method Fuzzer
=======================================
Tests dangerous HTTP methods on discovered endpoints.
Targets: TRACE (XST), PUT (file upload), DELETE, PATCH, OPTIONS enumeration.
"""

import logging
from dataclasses import dataclass
from app.scanner.dast.http.client import DASTHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class MethodFinding:
    method: str
    url: str
    issue: str
    description: str
    remediation: str
    severity: str
    confidence: str
    owasp: str
    cwe: str
    cvss_score: float
    evidence: str


def fuzz_methods(http_client: DASTHTTPClient, url: str) -> list[MethodFinding]:
    """
    Sends all dangerous HTTP methods to the URL and analyzes responses.
    Returns a list of MethodFinding objects.
    """
    findings = []

    # --- OPTIONS enumeration ---
    try:
        options_resp = http_client._send("OPTIONS", url)
        if options_resp.status_code not in (0, 400, 405):
            allowed = (options_resp.headers.get("Allow", "") or
                       options_resp.headers.get("allow", ""))
            if allowed:
                dangerous = [m for m in ["TRACE", "PUT", "DELETE", "CONNECT"] if m in allowed.upper()]
                if dangerous:
                    findings.append(MethodFinding(
                        method="OPTIONS",
                        url=url,
                        issue=f"Dangerous HTTP Methods Enabled: {', '.join(dangerous)}",
                        description=(
                            f"OPTIONS response reveals dangerous HTTP methods are allowed: {allowed}. "
                            f"These methods can be exploited for Cross-Site Tracing (TRACE), "
                            f"file upload (PUT), or data deletion (DELETE)."
                        ),
                        remediation=(
                            "Disable all HTTP methods not required by your application. "
                            "Restrict via web server configuration (Apache: LimitExcept, Nginx: limit_except)."
                        ),
                        severity="Medium",
                        confidence="Confirmed",
                        owasp="A05:2021",
                        cwe="CWE-749",
                        cvss_score=5.3,
                        evidence=f"OPTIONS {url}\nAllow: {allowed}\nStatus: {options_resp.status_code}",
                    ))
    except Exception as e:
        logger.debug(f"OPTIONS fuzz failed for {url}: {e}")

    # --- TRACE method (Cross-Site Tracing / XST) ---
    try:
        trace_resp = http_client._send("TRACE", url, headers={"X-Custom-Header-DevSecure": "xst-canary"})
        if trace_resp.status_code == 200 and "xst-canary" in trace_resp.body:
            findings.append(MethodFinding(
                method="TRACE",
                url=url,
                issue="HTTP TRACE Method Enabled — Cross-Site Tracing (XST) Vulnerability",
                description=(
                    "The TRACE HTTP method is enabled. TRACE echoes the request back to the client, "
                    "including custom headers such as cookies. This can be exploited via XST attacks "
                    "to steal cookies even with HttpOnly protection using JavaScript's XHR."
                ),
                remediation="Disable the TRACE method in your web server configuration.",
                severity="Medium",
                confidence="Confirmed",
                owasp="A05:2021",
                cwe="CWE-16",
                cvss_score=5.3,
                evidence=f"TRACE {url}\nStatus: {trace_resp.status_code}\n"
                         f"Response body (should not echo back): {trace_resp.body[:500]}",
            ))
    except Exception as e:
        logger.debug(f"TRACE fuzz failed for {url}: {e}")

    # --- PUT method (arbitrary file upload) ---
    try:
        test_path = url.rstrip("/") + "/devsecure360_put_test.txt"
        put_resp = http_client._send("PUT", test_path, data={"content": "devsecure360_rw_test"})
        if put_resp.status_code in (200, 201, 204):
            findings.append(MethodFinding(
                method="PUT",
                url=url,
                issue="HTTP PUT Method Enabled — Arbitrary File Upload Possible",
                description=(
                    f"The HTTP PUT method is enabled on this server. An attacker can upload "
                    f"arbitrary files including web shells, enabling full Remote Code Execution. "
                    f"A test PUT request to {test_path} returned HTTP {put_resp.status_code}."
                ),
                remediation="Disable the PUT method unless it is explicitly required by a REST API with proper authentication.",
                severity="High",
                confidence="Confirmed",
                owasp="A01:2021",
                cwe="CWE-434",
                cvss_score=8.6,
                evidence=f"PUT {test_path}\nStatus: {put_resp.status_code}",
            ))
    except Exception as e:
        logger.debug(f"PUT fuzz failed for {url}: {e}")

    # --- DELETE method ---
    try:
        delete_resp = http_client._send("DELETE", url)
        if delete_resp.status_code in (200, 204):
            findings.append(MethodFinding(
                method="DELETE",
                url=url,
                issue="HTTP DELETE Method Enabled Without Authentication Check",
                description=(
                    "The HTTP DELETE method returned a success response on this endpoint. "
                    "If not properly access-controlled, unauthenticated users can delete server-side resources."
                ),
                remediation="Ensure DELETE endpoints require authentication and authorization. Disable if not needed.",
                severity="High",
                confidence="Probable",
                owasp="A01:2021",
                cwe="CWE-285",
                cvss_score=7.5,
                evidence=f"DELETE {url}\nStatus: {delete_resp.status_code}",
            ))
    except Exception as e:
        logger.debug(f"DELETE fuzz failed for {url}: {e}")

    # --- CONNECT method ---
    try:
        connect_resp = http_client._send("CONNECT", url)
        if connect_resp.status_code in (200, 201):
            findings.append(MethodFinding(
                method="CONNECT",
                url=url,
                issue="HTTP CONNECT Method Enabled — Open Proxy Risk",
                description=(
                    "The CONNECT method is enabled. This can turn the server into an open proxy, "
                    "allowing attackers to pivot through your server to reach internal services."
                ),
                remediation="Disable the CONNECT method unless you intentionally run an HTTP proxy.",
                severity="High",
                confidence="Probable",
                owasp="A01:2021",
                cwe="CWE-441",
                cvss_score=7.5,
                evidence=f"CONNECT {url}\nStatus: {connect_resp.status_code}",
            ))
    except Exception as e:
        logger.debug(f"CONNECT fuzz failed for {url}: {e}")

    return findings
