"""
DevSecure360 — DAST Engine
============================
Entry point for website vulnerability scanning.
Orchestrates: crawl → payload injection → oracle detection → finding construction.

Interface:
    engine = DASTEngine()
    result: ScanResult = engine.scan(target_url="https://target.com")
"""

import uuid
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, urljoin
from typing import Optional

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

logger = logging.getLogger(__name__)


# CVSS scores for DAST finding classes — wired into the shared scoring engine
DAST_CVSS = {
    "SQLi":           {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "XSS":            {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "CMDi":           {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "Path Traversal": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "SSRF":           {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
    "XXE":            {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "SSTI":           {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "Open Redirect":  {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "CORS":           {"score": 5.4, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"},
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


class DASTEngine:
    """
    Proprietary DAST engine. No ZAP, no Nikto, no external tools.
    Takes a live URL → crawls → injects → confirms via oracle → returns ScanResult.
    """

    OOB_HOST = "127.0.0.1"
    OOB_PORT = 4444

    def __init__(self):
        self.http = DASTHTTPClient(timeout=15)
        self.oob = OOBListener(host=self.OOB_HOST, port=self.OOB_PORT)
        self._findings: list = []
        self._seen: set = set()   # dedup key: (vuln_class, url, param_name)

    def scan(self, target_url: str) -> ScanResult:
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()

        try:
            # Validate URL
            parsed = urlparse(target_url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(f"Invalid URL scheme: {parsed.scheme}")

            logger.info(f"[DAST] Starting scan: {target_url}")

            # Start OOB listener
            self.oob.start()

            # --- Phase 1: Crawl ---
            logger.info("[DAST] Crawling target...")
            html_crawler = HTMLCrawler(self.http, max_depth=3, max_pages=50)
            endpoints = html_crawler.crawl(target_url)

            spa_crawler = SPACrawler(max_pages=20)
            spa_endpoints = spa_crawler.crawl(target_url)
            endpoints.extend(spa_endpoints)

            # Always test the root URL with common param names even if no forms found
            if not endpoints:
                endpoints = [Endpoint(url=target_url, method="GET",
                                      params=[Param(name="q", location="query"),
                                              Param(name="id", location="query"),
                                              Param(name="url", location="query"),
                                              Param(name="file", location="query")])]

            logger.info(f"[DAST] Discovered {len(endpoints)} endpoints")

            # --- Phase 2: Test each endpoint ---
            for i, endpoint in enumerate(endpoints, 1):
                logger.info(f"[DAST] Testing endpoint {i}/{len(endpoints)}: {endpoint.method} {endpoint.url}")
                self._test_endpoint(endpoint, target_url)

            # --- Phase 3: CORS check on root ---
            self._test_cors(target_url)

            self.oob.stop()
            self.http.close()

            score = compute_score(self._findings)
            completed_at = datetime.now(timezone.utc).isoformat()

            logger.info(f"[DAST] Scan complete. {len(self._findings)} findings. Score: {score.get('score')}")

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

    def _test_endpoint(self, endpoint: Endpoint, base_url: str):
        if not endpoint.params:
            # No params — still try SSTI on URL path, SSRF on root
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

    # ── SQLi ──────────────────────────────────────────────────────────────────

    def _test_sqli(self, endpoint: Endpoint, param: Param):
        # Baseline request
        baseline = self._request(endpoint, param, param.default_value or "test")
        if baseline.status_code == 0:
            return

        # 1. Error-based
        for p in sqli_payloads.get_error_payloads():
            resp = self._request(endpoint, param, p.value)
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
                        f"into a SQL query without sanitization. A database error was returned "
                        f"confirming the injection: '{error_match}'."
                    ),
                    evidence=resp.raw_request,
                    remediation=(
                        "Use parameterized queries / prepared statements. Never concatenate "
                        "user input into SQL strings. Use an ORM or query builder."
                    ),
                    payload=p.value,
                )
                return  # one confirmed finding per param per vuln class is enough

        # 2. Boolean-based
        for true_p, false_p in sqli_payloads.get_boolean_pairs():
            resp_true = self._request(endpoint, param, true_p)
            resp_false = self._request(endpoint, param, false_p)
            diff = compare_responses(resp_true, resp_false)
            if diff.significant:
                self._add_finding(
                    vuln_class="SQLi",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"SQL Injection (boolean-based) in parameter '{param.name}'",
                    description=(
                        f"Boolean-based SQL injection detected. Responses differ significantly "
                        f"between true-condition and false-condition payloads."
                    ),
                    evidence=format_diff_evidence(resp_true, resp_false, param.name),
                    remediation="Use parameterized queries / prepared statements.",
                    payload=f"{true_p} vs {false_p}",
                )
                return

        # 3. Time-based (blind)
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
                        f"The parameter '{param.name}' is reflected in the response without "
                        f"sanitization. {'JavaScript execution confirmed by headless browser.' if executed else 'Payload reflected in HTML — likely XSS.'}"
                    ),
                    evidence=f"Payload: {payload}\nReflected in response: Yes\nJS executed: {executed}\n\n{resp.raw_request}",
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
                        f"Command injection confirmed. The unique canary token '{canary_id}' "
                        f"was returned in the response after injecting: {payload}"
                    ),
                    evidence=f"Payload: {payload}\nCanary in response: {canary_id}\n\n{resp.raw_request}",
                    remediation=(
                        "Never pass user input to shell commands. Use subprocess with "
                        "shell=False and a list of arguments. Whitelist acceptable values."
                    ),
                    payload=payload,
                )
                return

        # OOB-based
        oob_url = f"{self.OOB_HOST}:{self.OOB_PORT}"
        for payload in cmdi_payloads.get_oob_payloads(oob_url, canary_id):
            self._request(endpoint, param, payload)
            callback = self.oob.get_callback(canary_id, timeout=0.2)
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
            match = oracle.check_path_traversal(resp.body)
            if match:
                self._add_finding(
                    vuln_class="Path Traversal",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"Path Traversal in parameter '{param.name}'",
                    description=(
                        f"File read outside webroot confirmed. Response contained '{match}' "
                        f"after injecting traversal payload."
                    ),
                    evidence=f"Payload: {payload}\nOracle match: {match}\n\n{resp.raw_request}",
                    remediation=(
                        "Canonicalize file paths and validate they are inside the allowed directory. "
                        "Never build file paths from user input. Use os.path.abspath() and check prefix."
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

            # OOB callback confirmation (most reliable)
            callback = self.oob.get_callback(canary_id, timeout=0.2)
            if callback:
                self._add_finding(
                    vuln_class="SSRF",
                    url=endpoint.url,
                    param=param.name,
                    confidence="Confirmed",
                    issue=f"Server-Side Request Forgery in parameter '{param.name}'",
                    description="SSRF confirmed via OOB HTTP callback. The server made an outbound request to our listener.",
                    evidence=f"Payload: {payload}\nOOB callback:\n{callback}",
                    remediation=(
                        "Whitelist allowed URLs/domains for outbound requests. "
                        "Block access to private IP ranges and metadata endpoints. "
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
        """Test common SSRF-prone URL parameters by name heuristic."""
        ssrf_param_names = ["url", "redirect", "next", "target", "dest", "destination",
                            "link", "src", "source", "path", "callback", "return"]
        for name in ssrf_param_names:
            param = Param(name=name, location="query")
            self._test_ssrf(endpoint, param)

    # ── SSTI ──────────────────────────────────────────────────────────────────

    def _test_ssti(self, endpoint: Endpoint, param: Param):
        for payload, expected in ssti_payloads.get_detection_payloads():
            resp = self._request(endpoint, param, payload)
            if oracle.check_ssti(resp.body, expected):
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
                        "Use template engines in sandbox mode or escape all user values before rendering."
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
                    remediation=(
                        "Validate redirect targets against a whitelist of allowed destinations. "
                        "Never use raw user input as a redirect URL."
                    ),
                    payload=payload,
                )
                return

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
                    "Never reflect Origin dynamically when Allow-Credentials is true. "
                    "Never use wildcard (*) with credentials."
                ),
                payload=evil_origin,
            )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _request(self, endpoint: Endpoint, param: Param, payload_value: str,
                 allow_redirects: bool = True) -> HttpResponse:
        """Send a request with the payload injected into the target parameter."""
        # Build param map: all params at default, target param = payload
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
        """Deduplicate and add a finding."""
        dedup_key = (vuln_class, url, param)
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
            taint_trace=[],   # DAST uses evidence field, not taint_trace
            remediation=remediation,
            tool="devsecure_dast",
            cvss_score=cvss_info["score"],
            cvss_vector=cvss_info.get("vector"),
        )
        self._findings.append(finding)
        logger.info(f"[DAST] FINDING: {vuln_class} @ {url} param={param} ({confidence})")
