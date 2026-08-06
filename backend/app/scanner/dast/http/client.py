"""
DevSecure360 — DAST HTTP Client (Enterprise Edition)
======================================================
Uses `requests` library with:
- Persistent session (cookie/auth tracking across requests)
- Response streaming with 512KB body cap (prevents OOM on large assets)
- Binary content-type detection (skip body analysis on images/video)
- JSON body injection support
- Detailed raw_request reconstruction for evidence
- Configurable request delay for WAF-sensitive targets
"""

import requests
import urllib3
import time
import random
from typing import Optional
from dataclasses import dataclass, field

# Suppress per-request InsecureRequestWarning — we intentionally allow self-signed
# certs on test targets.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Content types that should NOT have their body analyzed (binary files)
BINARY_CONTENT_TYPES = (
    "image/", "video/", "audio/",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "font/",
)

# Maximum body size to read (512 KB). Prevents OOM on large JS/asset files.
MAX_BODY_BYTES = 512 * 1024


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
    is_binary: bool = False
    content_type: str = ""


class DASTHTTPClient:
    """
    HTTP client for DAST scanning.
    Uses requests with a persistent session for cookie/auth tracking.
    Supports GET, POST (form + JSON), and arbitrary HTTP methods for method fuzzing.
    """

    DEFAULT_TIMEOUT = 10  # seconds — enough for time-based payloads (5s sleep + margin)
    MAX_REDIRECTS = 10

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, request_delay_ms: int = 0):
        self.timeout = timeout
        self.request_delay_ms = request_delay_ms   # inter-request throttle for WAF-sensitive targets
        self.session = requests.Session()
        self.session.max_redirects = self.MAX_REDIRECTS
        self.session.headers.update({
            # Mimic a real browser to avoid bot detection / 403s
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

    def set_auth_cookie(self, name: str, value: str):
        """Inject an authentication cookie for authenticated scanning."""
        self.session.cookies.set(name, value)

    def set_auth_header(self, name: str, value: str):
        """Inject an auth header (e.g., Authorization: Bearer <token>)."""
        self.session.headers[name] = value

    def get(self, url: str, params: Optional[dict] = None,
            headers: Optional[dict] = None, allow_redirects: bool = True) -> HttpResponse:
        return self._send("GET", url, params=params, headers=headers,
                          allow_redirects=allow_redirects)

    def post(self, url: str, data: Optional[dict] = None, json: Optional[dict] = None,
             headers: Optional[dict] = None, allow_redirects: bool = True) -> HttpResponse:
        return self._send("POST", url, data=data, json=json, headers=headers,
                          allow_redirects=allow_redirects)

    def post_json(self, url: str, json_body: dict,
                  headers: Optional[dict] = None, allow_redirects: bool = True) -> HttpResponse:
        """POST a JSON body — for REST API injection."""
        merged = {"Content-Type": "application/json", **(headers or {})}
        return self._send("POST", url, json=json_body, headers=merged,
                          allow_redirects=allow_redirects)

    def _send(self, method: str, url: str, params: Optional[dict] = None,
              data=None, json=None,
              headers: Optional[dict] = None, allow_redirects: bool = True) -> HttpResponse:
        # Apply inter-request delay with jitter to look more human and avoid WAF throttling
        if self.request_delay_ms > 0:
            jitter = random.uniform(0, self.request_delay_ms * 0.3)
            time.sleep((self.request_delay_ms + jitter) / 1000.0)

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
                verify=False,     # Allow self-signed certs on test targets
                stream=True,      # Stream to cap body size
            )
            elapsed_ms = (time.time() - start) * 1000

            redirect_chain = [r.url for r in resp.history]
            content_type = resp.headers.get("Content-Type", "")

            # Detect binary content types — skip body analysis
            is_binary = any(ct in content_type for ct in BINARY_CONTENT_TYPES)

            # Read body with hard cap at MAX_BODY_BYTES
            if is_binary:
                body = ""
                resp.close()
            else:
                body_bytes = b""
                for chunk in resp.iter_content(chunk_size=8192):
                    body_bytes += chunk
                    if len(body_bytes) >= MAX_BODY_BYTES:
                        resp.close()
                        break
                body = body_bytes.decode("utf-8", errors="replace")

            # Build reconstructed request string for evidence field
            req = resp.request
            raw_request = f"{req.method} {req.url}\n"
            for k, v in (req.headers or {}).items():
                raw_request += f"{k}: {v}\n"
            if req.body:
                try:
                    raw_request += f"\n{req.body if isinstance(req.body, str) else req.body.decode('utf-8', errors='replace')}"
                except Exception:
                    raw_request += "\n[binary body]"

            raw_request += f"\n\n--- Response ({resp.status_code}) [{content_type}] in {elapsed_ms:.0f}ms ---\n"
            raw_request += body[:3000]   # cap snippet at 3000 chars

            return HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                response_time_ms=elapsed_ms,
                redirect_chain=redirect_chain,
                url=resp.url,
                raw_request=raw_request,
                is_binary=is_binary,
                content_type=content_type,
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
            elapsed_ms = (time.time() - start) * 1000
            return HttpResponse(
                status_code=0,
                headers={},
                body="",
                response_time_ms=elapsed_ms,
                redirect_chain=[],
                url=url,
                raw_request=f"{method} {url} [ERROR: {e}]",
            )

    def close(self):
        self.session.close()
