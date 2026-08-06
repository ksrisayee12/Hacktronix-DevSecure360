"""
DevSecure360 — DAST Engine (Enterprise Edition)
=================================================
Entry point for website vulnerability scanning.
Orchestrates: crawl → payload injection → oracle detection → finding construction.

Enterprise-grade capabilities:
- Security header analysis (HSTS, CSP, X-Frame-Options, cookies, etc.)
- HTTP method fuzzing (TRACE, PUT, DELETE, CONNECT)
- JSON body injection for REST API testing
- Concurrent endpoint scanning (ThreadPoolExecutor with jitter)
- Static asset skipping
- Comprehensive payload sets (SQLi, XSS, CMDi, Path Traversal, SSRF, SSTI, XXE, Open Redirect)
- OOB listener for blind vulnerability confirmation

Interface:
    engine = DASTEngine()
    result: ScanResult = engine.scan(target_url="https://target.com")
"""

import uuid
import logging
import random
import time
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.shared.types import (
    Finding, ScanResult, ScanStatus, ScanType, Severity
)
from app.utils.aggregator import compute_score

from app.scanner.dast.http.client import DASTHTTPClient, HttpResponse
from app.scanner.dast.crawler.html_crawler import HTMLCrawler, Endpoint, Param
from app.scanner.dast.crawler.spa_crawler import SPACrawler
from app.scanner.dast.oob.listener import OOBListener

from app.scanner.dast.payloads import sqli as sqli_payloads
from app.scanner.dast.payloads import xss as xss_payloads
from app.scanner.dast.payloads import cmdi as cmdi_payloads
from app.scanner.dast.payloads import path_traversal as path_traversal_payloads
from app.scanner.dast.payloads import ssrf as ssrf_payloads
from app.scanner.dast.payloads import ssti as ssti_payloads
from app.scanner.dast.payloads import open_redirect as open_redirect_payloads
from app.scanner.dast.payloads import xxe as xxe_payloads

from app.scanner.dast.detection import oracle
from app.scanner.dast.detection.differential import compare_responses, format_diff_evidence
from app.scanner.dast.checks.header_checks import check_security_headers, HeaderFinding
from app.scanner.dast.checks.method_fuzzer import fuzz_methods, MethodFinding

logger = logging.getLogger(__name__)


# ── CVSS / CWE / OWASP metadata ───────────────────────────────────────────────

DAST_CVSS = {
    "SQLi":              {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "XSS":               {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "CMDi":              {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "Path Traversal":    {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "SSRF":              {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
    "XXE":               {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "SSTI":              {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "Open Redirect":     {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "CORS":              {"score": 5.4, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"},
    "Missing HSTS":      {"score": 5.9, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "Missing CSP":       {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "Clickjacking":      {"score": 4.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "HTTP Method":       {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "Info Disclosure":   {"score": 3.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    "Cookie Security":   {"score": 5.4, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"},
}

DAST_CWE = {
    "SQLi":           "CWE-89",
    "XSS":            "CWE-79",
    "CMDi":           "CWE-78",
    "Path Traversal": "CWE-22",
    "SSRF":           "CWE-918",
    "XXE":            "CWE-611",
    "SSTI":           "CWE-94",
    "Open Redirect":  "CWE-601",
    "CORS":           "CWE-942",
}

DAST_OWASP = {
    "SQLi":           "A03:2021",
    "XSS":            "A03:2021",
    "CMDi":           "A03:2021",
    "Path Traversal": "A01:2021",
    "SSRF":           "A10:2021",
    "XXE":            "A05:2021",
    "SSTI":           "A03:2021",
    "Open Redirect":  "A01:2021",
    "CORS":           "A05:2021",
}


def _severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# Static file extensions to skip injection testing
STATIC_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".bmp",
    ".css", ".js", ".mjs",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi", ".mov",
    ".pdf", ".zip", ".tar", ".gz",
    ".json",  # skip pure JSON files, but NOT JSON API endpoints
)


class DASTEngine:
    """
    Enterprise DAST engine. No ZAP, no Nikto — pure proprietary scanning.
    Takes a live URL → crawls → injects → confirms via oracle → returns ScanResult.
    """

    OOB_HOST = "127.0.0.1"
    OOB_PORT = 4444

    def __init__(self):
        self.http = DASTHTTPClient(timeout=10, request_delay_ms=0)
        self.oob = OOBListener(host=self.OOB_HOST, port=self.OOB_PORT)
        self._findings: list = []
        self._findings_lock = threading.Lock()
        self._seen: set = set()

    def scan(self, target_url: str) -> ScanResult:
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()

        try:
            parsed = urlparse(target_url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(f"Invalid URL scheme: {parsed.scheme}")

            logger.info(f"[DAST] Starting enterprise scan: {target_url}")

            # Start OOB listener
            self.oob.start()

            # ── Phase 1: Crawl ─────────────────────────────────────────────────
            logger.info("[DAST] Phase 1: Crawling target (HTML + sitemap + robots.txt + JS)...")
            html_crawler = HTMLCrawler(self.http, max_depth=3, max_pages=75)
            endpoints = html_crawler.crawl(target_url)

            spa_crawler = SPACrawler(max_pages=20)
            spa_endpoints = spa_crawler.crawl(target_url)
            endpoints.extend(spa_endpoints)

            # Deduplicate
            seen_keys = set()
            unique_endpoints = []
            for ep in endpoints:
                key = f"{ep.method}:{ep.url}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    unique_endpoints.append(ep)
            endpoints = unique_endpoints

            # Always add root URL with common params if no endpoints found
            if not endpoints:
                from app.scanner.dast.crawler.html_crawler import FUZZ_PARAMS
                endpoints = [Endpoint(
                    url=target_url, method="GET",
                    params=[Param(name=p, location="query", default_value="test") for p in FUZZ_PARAMS[:10]]
                )]

            logger.info(f"[DAST] Discovered {len(endpoints)} unique endpoints")

            # ── Phase 2: Security Header Analysis (passive, fast) ──────────────
            logger.info("[DAST] Phase 2: Security header analysis...")
            root_resp = self.http.get(target_url)
            if root_resp.status_code > 0:
                # Pass cookies from session
                session_cookies = [
                    {"name": c.name, "value": c.value,
                     "httpOnly": False, "secure": c.secure or False,
                     "sameSite": getattr(c, "_rest", {}).get("SameSite", "")}
                    for c in self.http.session.cookies
                ]
                header_findings = check_security_headers(root_resp.headers, target_url, session_cookies)
                for hf in header_findings:
                    self._add_header_finding(hf, target_url)
                logger.info(f"[DAST] Header analysis: {len(header_findings)} issues found")

            # ── Phase 3: HTTP Method Fuzzing ───────────────────────────────────
            logger.info("[DAST] Phase 3: HTTP method fuzzing...")
            method_findings = fuzz_methods(self.http, target_url)
            for mf in method_findings:
                self._add_method_finding(mf)
            logger.info(f"[DAST] Method fuzzing: {len(method_findings)} issues found")

            # ── Phase 4: CORS Check ────────────────────────────────────────────
            logger.info("[DAST] Phase 4: CORS misconfiguration check...")
            self._test_cors(target_url)

            # ── Phase 5: Concurrent Endpoint Attack ────────────────────────────
            logger.info(f"[DAST] Phase 5: Attacking {len(endpoints)} endpoints concurrently...")

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for i, endpoint in enumerate(endpoints, 1):
                    futures.append(executor.submit(self._test_endpoint, endpoint, target_url, i, len(endpoints)))

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"[DAST] Endpoint test failed: {e}")

            self.oob.stop()
            self.http.close()

            score = compute_score(self._findings)
            completed_at = datetime.now(timezone.utc).isoformat()

            logger.info(
                f"[DAST] Scan complete. {len(self._findings)} findings. "
                f"Score: {score.get('score')} | Grade: {score.get('grade')}"
            )

            return ScanResult(
                scan_id=scan_id,
                scan_type=ScanType.DAST,
                status=ScanStatus.COMPLETED,
                target=target_url,
                findings=self._findings,
                score=score,
                started_at=started_at,
                completed_at=completed_at,
                error=None,
            )

        except Exception as e:
            logger.error(f"[DAST] Scan failed: {e}", exc_info=True)
            self.oob.stop()
            self.http.close()
            return ScanResult(
                scan_id=scan_id,
                scan_type=ScanType.DAST,
                status=ScanStatus.FAILED,
                target=target_url,
                findings=self._findings,
                score=None,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error=str(e),
            )

    # ── Per-endpoint test dispatcher ──────────────────────────────────────────

    def _test_endpoint(self, endpoint: Endpoint, base_url: str, index: int = 0, total: int = 0):
        if index and total:
            logger.info(f"[DAST] Testing endpoint {index}/{total}: {endpoint.method} {endpoint.url}")

        # Skip static asset files
        path = urlparse(endpoint.url).path.lower()
        if any(path.endswith(ext) for ext in STATIC_EXTS):
            return

        if not endpoint.params:
            # No params — test with SSRF heuristic params only
            self._test_ssrf_endpoint(endpoint)
            return

        for param in endpoint.params:
            self._test_sqli(endpoint, param)
            self._test_xss(endpoint, param)
            self._test_cmdi(endpoint, param)
            self._test_path_traversal(endpoint, param)
            self._test_ssrf(endpoint, param)
            self._test_ssti(endpoint, param)
            self._test_open_redirect(endpoint, param)
            self._test_xxe(endpoint, param)

        # Also test JSON body injection if POST endpoint
        if endpoint.method == "POST":
            self._test_json_injection(endpoint)

    # ── SQLi ──────────────────────────────────────────────────────────────────

    def _test_sqli(self, endpoint: Endpoint, param: Param):
        baseline = self._request(endpoint, param, param.default_value or "1")
        if baseline.status_code == 0:
            return

        # 1. Error-based
        for p in sqli_payloads.get_error_payloads():
            resp = self._request(endpoint, param, p.value)
            if resp.status_code == 0:
                continue
            error_match = oracle.check_sqli_error(resp.body)
            if error_match:
                self._add_finding(
                    vuln_class="SQLi",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"SQL Injection (error-based) in parameter '{param.name}'",
                    description=(
                        f"The parameter '{param.name}' on {endpoint.url} is directly interpolated "
                        f"into a SQL query. A database error was returned confirming injection: '{error_match}'."
                    ),
                    evidence=resp.raw_request,
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                    payload=p.value,
                )
                return

        # 2. Boolean-based differential
        for true_p, false_p in sqli_payloads.get_boolean_pairs():
            resp_true = self._request(endpoint, param, true_p)
            resp_false = self._request(endpoint, param, false_p)
            if resp_true.status_code == 0 or resp_false.status_code == 0:
                continue
            diff = compare_responses(resp_true, resp_false)
            if diff.significant:
                self._add_finding(
                    vuln_class="SQLi",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"SQL Injection (boolean-based blind) in parameter '{param.name}'",
                    description=(
                        f"Boolean-based SQL injection detected. True-condition payload returns significantly "
                        f"different response than false-condition payload."
                    ),
                    evidence=format_diff_evidence(resp_true, resp_false, param.name),
                    remediation="Use parameterized queries / prepared statements.",
                    payload=f"true: {true_p} | false: {false_p}",
                )
                return

        # 3. Time-based blind
        for p in sqli_payloads.get_time_payloads():
            resp = self._request(endpoint, param, p.value)
            if oracle.check_sqli_time(resp.response_time_ms, baseline.response_time_ms):
                self._add_finding(
                    vuln_class="SQLi",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"SQL Injection (time-based blind) in parameter '{param.name}'",
                    description=(
                        f"Time-based blind SQL injection confirmed. SLEEP payload caused "
                        f"{resp.response_time_ms:.0f}ms response (baseline: {baseline.response_time_ms:.0f}ms)."
                    ),
                    evidence=(
                        f"Payload: {p.value}\nResponse time: {resp.response_time_ms:.0f}ms\n"
                        f"Baseline: {baseline.response_time_ms:.0f}ms\n\n{resp.raw_request}"
                    ),
                    remediation="Use parameterized queries / prepared statements.",
                    payload=p.value,
                )
                return

    # ── XSS ──────────────────────────────────────────────────────────────────

    def _test_xss(self, endpoint: Endpoint, param: Param):
        canary_id = self.oob.generate_canary("xss")
        marker = xss_payloads.xss_canary_marker(canary_id)

        for payload in xss_payloads.get_reflected_payloads(canary_id):
            resp = self._request(endpoint, param, payload)
            if resp.status_code == 0:
                continue
            reflected = oracle.check_xss_reflection(resp.body, payload)
            if reflected:
                executed = oracle.check_xss_executed(resp.url, marker)
                confidence = "Confirmed" if executed else "Probable"
                self._add_finding(
                    vuln_class="XSS",
                    url=endpoint.url,
                    param=param.name,
                    confidence=confidence,
                    issue=f"Cross-Site Scripting (reflected) in parameter '{param.name}'",
                    description=(
                        f"The parameter '{param.name}' is reflected in the response without sanitization. "
                        f"{'JavaScript execution confirmed by headless browser.' if executed else 'Payload reflected in HTML — likely XSS.'}"
                    ),
                    evidence=f"Payload: {payload}\nReflected: Yes\nExecuted: {executed}\n\n{resp.raw_request}",
                    remediation=(
                        "HTML-encode all user input before rendering. Use Content-Security-Policy. "
                        "Never insert user data directly into innerHTML or event handlers."
                    ),
                    payload=payload,
                )
                return

    # ── CMDi ──────────────────────────────────────────────────────────────────

    def _test_cmdi(self, endpoint: Endpoint, param: Param):
        canary_id = self.oob.generate_canary("cmdi")

        # Echo-based (in-band)
        for payload in cmdi_payloads.get_payloads(canary_id):
            resp = self._request(endpoint, param, payload)
            if oracle.check_cmdi_echo(resp.body, canary_id):
                self._add_finding(
                    vuln_class="CMDi",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"OS Command Injection in parameter '{param.name}'",
                    description=(
                        f"Command injection confirmed. Canary token '{canary_id}' "
                        f"returned in response after injecting: {payload}"
                    ),
                    evidence=f"Payload: {payload}\nCanary in response: {canary_id}\n\n{resp.raw_request}",
                    remediation="Never pass user input to shell commands. Use subprocess with shell=False.",
                    payload=payload,
                )
                return

        # OOB-based
        oob_url = f"{self.OOB_HOST}:{self.OOB_PORT}"
        for payload in cmdi_payloads.get_oob_payloads(oob_url, canary_id):
            self._request(endpoint, param, payload)
            callback = self.oob.get_callback(canary_id, timeout=0.3)
            if callback:
                self._add_finding(
                    vuln_class="CMDi",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"Blind OS Command Injection (OOB) in parameter '{param.name}'",
                    description="Out-of-band command injection confirmed via OOB HTTP callback.",
                    evidence=f"Payload: {payload}\nOOB callback:\n{callback}",
                    remediation="Never pass user input to shell commands.",
                    payload=payload,
                )
                return

    # ── Path Traversal ─────────────────────────────────────────────────────────

    def _test_path_traversal(self, endpoint: Endpoint, param: Param):
        for payload in path_traversal_payloads.get_payloads():
            resp = self._request(endpoint, param, payload)
            if resp.status_code == 0:
                continue
            match = oracle.check_path_traversal(resp.body)
            if match:
                self._add_finding(
                    vuln_class="Path Traversal",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"Path Traversal / Local File Inclusion in parameter '{param.name}'",
                    description=(
                        f"File read outside webroot confirmed. Response contained '{match}' "
                        f"after injecting traversal payload."
                    ),
                    evidence=f"Payload: {payload}\nOracle match: {match}\n\n{resp.raw_request}",
                    remediation=(
                        "Canonicalize file paths and validate they are inside the allowed directory. "
                        "Never build file paths from user input."
                    ),
                    payload=payload,
                )
                return

    # ── SSRF ──────────────────────────────────────────────────────────────────

    def _test_ssrf(self, endpoint: Endpoint, param: Param):
        canary_id = self.oob.generate_canary("ssrf")
        oob_host = f"{self.OOB_HOST}:{self.OOB_PORT}"

        for payload in ssrf_payloads.get_payloads(oob_host, canary_id):
            resp = self._request(endpoint, param, payload)
            if resp.status_code == 0:
                continue

            # OOB callback confirmation
            callback = self.oob.get_callback(canary_id, timeout=0.3)
            if callback:
                self._add_finding(
                    vuln_class="SSRF",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"Server-Side Request Forgery in parameter '{param.name}'",
                    description="SSRF confirmed via OOB HTTP callback. Server made an outbound request to our listener.",
                    evidence=f"Payload: {payload}\nOOB callback:\n{callback}",
                    remediation=(
                        "Whitelist allowed URLs/domains. Block private IP ranges and metadata endpoints. "
                        "Use a dedicated HTTP proxy with egress filtering."
                    ),
                    payload=payload,
                )
                return

            # In-band metadata response check
            for oracle_str in ssrf_payloads.INTERNAL_ORACLE_STRINGS:
                if oracle_str.lower() in resp.body.lower():
                    self._add_finding(
                        vuln_class="SSRF",
                        url=endpoint.url,
                        param=param.name,
                        confidence="Confirmed",
                        issue=f"Server-Side Request Forgery (metadata access) in parameter '{param.name}'",
                        description=f"SSRF confirmed. Response contained internal metadata string: '{oracle_str}'",
                        evidence=f"Payload: {payload}\nOracle match: {oracle_str}\n\n{resp.raw_request}",
                        remediation="Whitelist allowed URLs. Block metadata endpoints.",
                        payload=payload,
                    )
                    return

    def _test_ssrf_endpoint(self, endpoint: Endpoint):
        """Test common SSRF-prone URL parameters by name heuristic on parameterless endpoints."""
        ssrf_param_names = ["url", "redirect", "next", "src", "dest", "target"]
        for name in ssrf_param_names:
            param = Param(name=name, location="query")
            self._test_ssrf(endpoint, param)

    # ── SSTI ──────────────────────────────────────────────────────────────────

    def _test_ssti(self, endpoint: Endpoint, param: Param):
        for payload, expected in ssti_payloads.get_detection_payloads():
            resp = self._request(endpoint, param, payload)
            if resp.status_code == 0:
                continue
            if oracle.check_ssti(resp.body, expected):
                # Verify: the expected value must NOT appear in the baseline (avoid false positives)
                baseline = self._request(endpoint, param, param.default_value or "test_baseline")
                if expected in baseline.body:
                    continue  # pre-existing content — not a real finding

                self._add_finding(
                    vuln_class="SSTI",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"Server-Side Template Injection in parameter '{param.name}'",
                    description=(
                        f"Template injection confirmed. Payload '{payload}' was evaluated "
                        f"by the template engine and returned '{expected}'."
                    ),
                    evidence=f"Payload: {payload}\nExpected in response: {expected}\n\n{resp.raw_request}",
                    remediation=(
                        "Never pass user input directly into template strings. "
                        "Use template engines in sandbox mode or escape all user values."
                    ),
                    payload=payload,
                )
                return

    # ── Open Redirect ──────────────────────────────────────────────────────────

    def _test_open_redirect(self, endpoint: Endpoint, param: Param):
        for payload in open_redirect_payloads.get_payloads():
            resp = self._request(endpoint, param, payload, allow_redirects=False)
            match = oracle.check_open_redirect(resp.headers, open_redirect_payloads.ORACLE_DOMAIN,
                                                resp.redirect_chain)
            if match:
                self._add_finding(
                    vuln_class="Open Redirect",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"Open Redirect in parameter '{param.name}'",
                    description=(
                        f"Open redirect confirmed. Parameter '{param.name}' caused a redirect "
                        f"to the injected external domain: {match}"
                    ),
                    evidence=f"Payload: {payload}\nRedirect to: {match}\n\n{resp.raw_request}",
                    remediation="Validate redirect targets against a whitelist of allowed destinations.",
                    payload=payload,
                )
                return

    # ── XXE ───────────────────────────────────────────────────────────────────

    def _test_xxe(self, endpoint: Endpoint, param: Param):
        for payload in xxe_payloads.get_payloads():
            # Only inject XXE on POST endpoints or XML-accepting endpoints
            if endpoint.method not in ("POST", "PUT", "PATCH"):
                continue
            headers = {"Content-Type": "application/xml"}
            resp = self.http.post(endpoint.url, data=payload, headers=headers)
            match = oracle.check_xxe(resp.body)
            if match:
                self._add_finding(
                    vuln_class="XXE",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"XML External Entity (XXE) Injection",
                    description=(
                        f"XXE confirmed. File contents appeared in response after injecting "
                        f"malicious XML entity: '{match}'"
                    ),
                    evidence=f"Payload:\n{payload}\nOracle match: {match}\n\n{resp.raw_request}",
                    remediation=(
                        "Disable external entity processing in your XML parser. "
                        "Use JSON where possible. Never deserialize untrusted XML."
                    ),
                    payload=payload,
                )
                return

    # ── JSON injection (REST API testing) ─────────────────────────────────────

    def _test_json_injection(self, endpoint: Endpoint):
        """
        Test POST endpoints that might accept JSON by re-injecting all payloads
        as JSON body parameters. Covers REST APIs that reject form data.
        """
        baseline_json = {p.name: p.default_value or "test" for p in endpoint.params}

        for param in endpoint.params:
            # SQLi in JSON
            for p in sqli_payloads.get_error_payloads()[:5]:   # top 5 only for speed
                test_json = {**baseline_json, param.name: p.value}
                resp = self.http.post_json(endpoint.url, test_json)
                if resp.status_code == 0:
                    continue
                error_match = oracle.check_sqli_error(resp.body)
                if error_match:
                    self._add_finding(
                        vuln_class="SQLi",
                        url=endpoint.url,
                        param=f"{param.name} (JSON body)",
                        confidence="Confirmed",
                        issue=f"SQL Injection via JSON body parameter '{param.name}'",
                        description=(
                            f"SQL injection in JSON body parameter '{param.name}'. "
                            f"A database error was returned: '{error_match}'."
                        ),
                        evidence=f"JSON payload: {test_json}\nError: {error_match}\n\n{resp.raw_request}",
                        remediation="Use parameterized queries even when accepting JSON input.",
                        payload=str(test_json),
                    )
                    break

            # XSS in JSON response
            canary_id = self.oob.generate_canary("xss_json")
            xss_payload = xss_payloads.get_reflected_payloads(canary_id)[0]
            test_json = {**baseline_json, param.name: xss_payload}
            resp = self.http.post_json(endpoint.url, test_json)
            if resp.status_code > 0 and oracle.check_xss_reflection(resp.body, xss_payload):
                self._add_finding(
                    vuln_class="XSS",
                    url=endpoint.url,
                    param=f"{param.name} (JSON body)",
                    confidence="Probable",
                    issue=f"XSS via JSON body parameter '{param.name}'",
                    description=f"XSS payload reflected in response when injected via JSON body.",
                    evidence=f"JSON payload: {test_json}\n\n{resp.raw_request}",
                    remediation="Encode output regardless of input content type.",
                    payload=xss_payload,
                )
                break

    # ── CORS ──────────────────────────────────────────────────────────────────

    def _test_cors(self, url: str):
        evil_origin = "https://evil.devsecure360.io"
        resp = self.http.get(url, headers={"Origin": evil_origin})
        match = oracle.check_cors_misconfiguration(resp.headers, evil_origin)
        if match:
            self._add_finding(
                vuln_class="CORS",
                url=url,
                param="Origin header",
                confidence="Confirmed",
                issue="CORS Misconfiguration — Arbitrary Origin Reflected with Credentials",
                description=(
                    "The server reflects any Origin header and allows credentials. "
                    "An attacker's page can make credentialed cross-origin requests and read responses."
                ),
                evidence=f"Origin sent: {evil_origin}\nServer responded: {match}\n\n{resp.raw_request}",
                remediation=(
                    "Maintain an explicit whitelist of allowed origins. "
                    "Never reflect Origin dynamically when Allow-Credentials is true."
                ),
                payload=evil_origin,
            )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _request(self, endpoint: Endpoint, param: Param, payload_value: str,
                 allow_redirects: bool = True) -> HttpResponse:
        """Send a request with the payload injected into the target parameter."""
        params_map = {p.name: p.default_value for p in endpoint.params}
        params_map[param.name] = payload_value

        if endpoint.method == "POST":
            return self.http.post(endpoint.url, data=params_map,
                                  allow_redirects=allow_redirects)
        else:
            return self.http.get(endpoint.url, params=params_map,
                                 allow_redirects=allow_redirects)

    def _add_finding(self, vuln_class: str, url: str, param: str,
                     confidence: str, issue: str, description: str,
                     evidence: str, remediation: str, payload: str = ""):
        """Thread-safe deduplicated finding addition."""
        dedup_key = (vuln_class, url, param)
        with self._findings_lock:
            if dedup_key in self._seen:
                return
            self._seen.add(dedup_key)

        cvss_info = DAST_CVSS.get(vuln_class, {"score": 5.0, "vector": ""})
        severity = _severity_from_cvss(cvss_info["score"])

        finding = Finding(
            id=str(uuid.uuid4()),
            rule_id=f"dast_{vuln_class.lower().replace(' ', '_')}_{param[:20]}",
            vuln_class=vuln_class,
            scan_type=ScanType.DAST,
            file=None,
            line=None,
            url=url,
            severity=severity,
            confidence=confidence,
            cwe=DAST_CWE.get(vuln_class),
            owasp=DAST_OWASP.get(vuln_class),
            issue=issue,
            description=description,
            evidence=evidence,
            taint_trace=[],
            remediation=remediation,
            tool="devsecure_dast",
            cvss_score=cvss_info["score"],
            cvss_vector=cvss_info.get("vector"),
        )

        with self._findings_lock:
            self._findings.append(finding)

        logger.info(f"[DAST] FINDING: {vuln_class} @ {url} param={param} ({confidence})")

    def _add_header_finding(self, hf: HeaderFinding, url: str):
        """Convert a HeaderFinding to a Finding and add it."""
        # Map severity string → enum
        sev_map = {
            "Critical": Severity.CRITICAL, "High": Severity.HIGH,
            "Medium": Severity.MEDIUM, "Low": Severity.LOW,
        }
        severity = sev_map.get(hf.severity, Severity.LOW)

        finding = Finding(
            id=str(uuid.uuid4()),
            rule_id=f"dast_header_{hf.issue[:40].lower().replace(' ', '_')}",
            vuln_class="Security Header",
            scan_type=ScanType.DAST,
            file=None, line=None,
            url=url,
            severity=severity,
            confidence=hf.confidence,
            cwe=hf.cwe,
            owasp=hf.owasp,
            issue=hf.issue,
            description=hf.description,
            evidence=f"URL: {url}\nHeader check: {hf.issue}",
            taint_trace=[],
            remediation=hf.remediation,
            tool="devsecure_dast",
            cvss_score=hf.cvss_score,
            cvss_vector=DAST_CVSS.get("Info Disclosure", {}).get("vector", ""),
        )

        with self._findings_lock:
            self._findings.append(finding)

    def _add_method_finding(self, mf: MethodFinding):
        """Convert a MethodFinding to a Finding and add it."""
        sev_map = {"Critical": Severity.CRITICAL, "High": Severity.HIGH,
                   "Medium": Severity.MEDIUM, "Low": Severity.LOW}
        severity = sev_map.get(mf.severity, Severity.LOW)

        finding = Finding(
            id=str(uuid.uuid4()),
            rule_id=f"dast_method_{mf.method.lower()}",
            vuln_class="HTTP Method",
            scan_type=ScanType.DAST,
            file=None, line=None,
            url=mf.url,
            severity=severity,
            confidence=mf.confidence,
            cwe=mf.cwe,
            owasp=mf.owasp,
            issue=mf.issue,
            description=mf.description,
            evidence=mf.evidence,
            taint_trace=[],
            remediation=mf.remediation,
            tool="devsecure_dast",
            cvss_score=mf.cvss_score,
            cvss_vector=DAST_CVSS.get("HTTP Method", {}).get("vector", ""),
        )

        with self._findings_lock:
            self._findings.append(finding)
