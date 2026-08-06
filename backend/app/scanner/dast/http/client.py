"""
DevSecure360 — DAST HTTP Client
================================
Uses the `requests` library for reliable HTTP communication.
Handles sessions, cookies, redirects, custom headers, and timing.
"""

import requests
import time
import uuid
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class HttpResponse:
    """Standardized HTTP response object."""
    status_code: int
    headers: dict
    body: str
    response_time_ms: float
    redirect_chain: list  # list of URLs followed
    url: str              # final URL after redirects
    raw_request: str      # reconstructed request string for evidence


class DASTHTTPClient:
    """
    HTTP client for DAST scanning.
    Uses requests with a persistent session for cookie/auth tracking.
    """

    DEFAULT_TIMEOUT = 15  # seconds
    MAX_REDIRECTS = 10

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.max_redirects = self.MAX_REDIRECTS
        self.session.headers.update({
            "User-Agent": "DevSecure360-DAST/1.0 (Security Scanner)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        })

    def get(self, url: str, params: Optional[dict] = None,
            headers: Optional[dict] = None, allow_redirects: bool = True) -> HttpResponse:
        return self._send("GET", url, params=params, headers=headers,
                          allow_redirects=allow_redirects)

    def post(self, url: str, data: Optional[dict] = None, json: Optional[dict] = None,
             headers: Optional[dict] = None, allow_redirects: bool = True) -> HttpResponse:
        return self._send("POST", url, data=data, json=json, headers=headers,
                          allow_redirects=allow_redirects)

    def _send(self, method: str, url: str, params: Optional[dict] = None,
              data: Optional[dict] = None, json: Optional[dict] = None,
              headers: Optional[dict] = None, allow_redirects: bool = True) -> HttpResponse:
        merged_headers = {**(headers or {})}
        start = time.time()
        try:
            resp = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json,
                headers=merged_headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=False,  # Allow self-signed certs on test targets
            )
            elapsed_ms = (time.time() - start) * 1000

            redirect_chain = [r.url for r in resp.history]

            # Build reconstructed request string for evidence field
            req = resp.request
            raw_request = f"{req.method} {req.url}\n"
            for k, v in req.headers.items():
                raw_request += f"{k}: {v}\n"
            if req.body:
                raw_request += f"\n{req.body}"

            raw_request += f"\n\n--- Response ({resp.status_code}) in {elapsed_ms:.0f}ms ---\n"
            raw_request += f"{resp.text[:2000]}"  # cap response snippet at 2000 chars

            return HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                response_time_ms=elapsed_ms,
                redirect_chain=redirect_chain,
                url=resp.url,
                raw_request=raw_request,
            )

        except requests.exceptions.Timeout:
            elapsed_ms = (time.time() - start) * 1000
            return HttpResponse(
                status_code=0,
                headers={},
                body="",
                response_time_ms=elapsed_ms,
                redirect_chain=[],
                url=url,
                raw_request=f"{method} {url} [TIMEOUT after {elapsed_ms:.0f}ms]",
            )
        except requests.exceptions.RequestException as e:
            return HttpResponse(
                status_code=0,
                headers={},
                body="",
                response_time_ms=0,
                redirect_chain=[],
                url=url,
                raw_request=f"{method} {url} [ERROR: {e}]",
            )

    def close(self):
        self.session.close()
