"""
DevSecure360 — DAST Detection Oracle
========================================
Proof-of-exploitation detection. No string matching on chat output.
Every confirmed finding requires an observable, verifiable result:
  - A database error string
  - A response time delta above threshold
  - A JS expression that evaluated (headless browser)
  - A unique canary token in the response body
  - A Location header containing the injected URL
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# --- SQL Injection Oracle ---

SQLI_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"mysql_fetch_array\(\)",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"sql syntax.*mysql",
    r"mysql_num_rows\(\)",
    # PostgreSQL
    r"pg::syntaxerror",
    r"pg_query\(\)",
    r"org\.postgresql\.util\.psqlexception",
    r"error:.*syntax error at",
    # MSSQL
    r"unclosed quotation mark after the character string",
    r"incorrect syntax near",
    r"microsoft.*sql.*server",
    r"mssql_query\(\)",
    r"\[microsoft\]\[sql server\]",
    # Oracle
    r"ora-\d{4,5}",
    r"oracle.*driver",
    r"oracle.*odbc",
    # SQLite
    r"sqlite3\.",
    r"sqlite_error",
    r"sqlite.*exception",
    # Generic
    r"sql command not properly ended",
    r"quoted string not properly terminated",
    r"syntax error.*unexpected",
]


def check_sqli_error(body: str) -> Optional[str]:
    """
    Checks response body for DB-specific error strings.
    Returns the matched pattern if found, else None.
    """
    body_lower = body.lower()
    for pattern in SQLI_ERROR_PATTERNS:
        m = re.search(pattern, body_lower)
        if m:
            return m.group(0)
    return None


def check_sqli_time(response_time_ms: float, baseline_ms: float, threshold_ms: float = 4500) -> bool:
    """
    Confirms time-based SQLi by comparing response time to baseline.
    The SLEEP(5) payload adds ~5000ms; we use a conservative 4500ms threshold.
    """
    return response_time_ms >= threshold_ms and response_time_ms >= (baseline_ms + 3000)


# --- XSS Oracle ---

def check_xss_reflection(body: str, payload: str) -> bool:
    """
    Naive reflection check: did the raw payload appear verbatim in the response?
    Used as a heuristic. Full confirmation uses headless browser (check_xss_executed).
    """
    return payload in body


def check_xss_executed(url: str, canary_marker: str) -> bool:
    """
    Headless browser check: navigate to URL, see if window.__xss_<canary> is set.
    Requires Playwright. Falls back gracefully if not installed.
    Returns True if XSS JavaScript actually executed.
    """
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_context(ignore_https_errors=True).new_page()
            try:
                page.goto(url, timeout=10000, wait_until="networkidle")
            except Exception:
                pass
            result = page.evaluate(f"() => window.{canary_marker}")
            browser.close()
            return bool(result)
    except ImportError:
        logger.warning("Playwright not available — XSS confirmation via headless browser skipped. "
                       "Reporting as 'Probable' instead of 'Confirmed'.")
        return False
    except Exception as e:
        logger.debug(f"XSS headless check failed: {e}")
        return False


# --- CMDi Oracle ---

def check_cmdi_echo(body: str, canary_id: str) -> bool:
    """
    Confirms CMDi by checking if the unique canary token appears in the response body.
    """
    return canary_id in body


def check_cmdi_time(response_time_ms: float, baseline_ms: float, threshold_ms: float = 4500) -> bool:
    """Time-based CMDi detection (same method as time-based SQLi)."""
    return response_time_ms >= threshold_ms and response_time_ms >= (baseline_ms + 3000)


# --- Path Traversal Oracle ---

from app.scanner.dast.payloads.path_traversal import LINUX_ORACLE_STRINGS, WINDOWS_ORACLE_STRINGS


def check_path_traversal(body: str) -> Optional[str]:
    """
    Confirms path traversal if /etc/passwd content or win.ini content appears in response.
    Returns the matched string as evidence.
    """
    for s in LINUX_ORACLE_STRINGS:
        if s in body:
            return s
    for s in WINDOWS_ORACLE_STRINGS:
        if s.lower() in body.lower():
            return s
    return None


# --- SSTI Oracle ---

def check_ssti(body: str, expected_value: str) -> bool:
    """
    Confirms SSTI if the evaluated math result appears in the response.
    e.g. {{7*7}} should produce '49'.
    """
    return expected_value in body


# --- Open Redirect Oracle ---

def check_open_redirect(response_headers: dict, injected_domain: str,
                        redirect_chain: list) -> Optional[str]:
    """
    Confirms open redirect if:
    - The Location header contains the injected domain, OR
    - The redirect chain followed a URL containing the injected domain.
    """
    location = response_headers.get("Location", "") or response_headers.get("location", "")
    if injected_domain in location:
        return f"Location header: {location}"
    for url in redirect_chain:
        if injected_domain in url:
            return f"Redirect chain included: {url}"
    return None


# --- CORS Misconfiguration Oracle ---

def check_cors_misconfiguration(response_headers: dict, injected_origin: str = "https://evil.devsecure360.io") -> Optional[str]:
    """
    Confirms CORS misconfiguration when:
    - Access-Control-Allow-Origin reflects the injected evil origin
    - AND Access-Control-Allow-Credentials is 'true'
    This combination allows a malicious page to make credentialed cross-origin requests.
    """
    acao = response_headers.get("Access-Control-Allow-Origin", "")
    acac = response_headers.get("Access-Control-Allow-Credentials", "")
    if injected_origin in acao and acac.lower() == "true":
        return f"ACAO: {acao}, ACAC: {acac}"
    # Wildcard with credentials is also a misconfiguration (browsers block it, but it's a config error)
    if acao == "*" and acac.lower() == "true":
        return f"ACAO: * with ACAC: true (browsers block credentials, but misconfigured)"
    return None


# --- XXE Oracle ---

from app.scanner.dast.payloads.xxe import XXE_ORACLE_STRINGS


def check_xxe(body: str) -> Optional[str]:
    """Confirms XXE if file contents appear in the response."""
    for s in XXE_ORACLE_STRINGS:
        if s in body:
            return s
    return None
