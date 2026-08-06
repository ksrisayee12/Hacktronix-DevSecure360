"""
DevSecure360 — DAST HTML Crawler
=================================
Parses static HTML pages with BeautifulSoup4.
Discovers: links, forms, API endpoints referenced in inline JS.
"""

from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from typing import Optional
import re

from app.scanner.dast.http.client import DASTHTTPClient


@dataclass
class Param:
    """A single input parameter on an endpoint."""
    name: str
    location: str   # "query" | "body" | "cookie" | "header" | "path"
    default_value: str = ""


@dataclass
class Endpoint:
    """A discovered endpoint with its input parameters."""
    url: str
    method: str             # GET | POST
    params: list = field(default_factory=list)   # list[Param]
    content_type: str = "application/x-www-form-urlencoded"


class HTMLCrawler:
    """
    Crawls a target URL and discovers all endpoints and input parameters.
    Uses BeautifulSoup4 for HTML parsing.
    """

    # JS patterns that often reveal API endpoints
    JS_ENDPOINT_PATTERNS = [
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        r'XMLHttpRequest[^"]*open\(["\'](?:GET|POST)["\'],\s*["\']([^"\']+)["\']',
        r'\$\.(ajax|get|post)\(\s*["\']([^"\']+)["\']',
    ]

    def __init__(self, http_client: DASTHTTPClient, max_depth: int = 3, max_pages: int = 50):
        self.client = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: set = set()
        self.endpoints: list = []

    def crawl(self, base_url: str) -> list:
        """
        Crawls the base URL up to max_depth. Returns list[Endpoint].
        """
        self.base_domain = urlparse(base_url).netloc
        self._crawl_url(base_url, depth=0)
        return self.endpoints

    def _crawl_url(self, url: str, depth: int):
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return

        self.visited.add(url)

        resp = self.client.get(url)
        if resp.status_code == 0 or not resp.body:
            return

        soup = BeautifulSoup(resp.body, "html.parser")

        # --- Extract base URL for relative link resolution ---
        base_tag = soup.find("base", href=True)
        base = base_tag["href"] if base_tag else url

        # --- Process forms ---
        for form in soup.find_all("form"):
            self._process_form(form, base)

        # --- Extract query params from current URL ---
        parsed = urlparse(url)
        if parsed.query:
            params = [Param(name=k, location="query", default_value=v[0] if v else "")
                      for k, v in parse_qs(parsed.query).items()]
            if params:
                endpoint = Endpoint(url=url, method="GET", params=params)
                if endpoint not in self.endpoints:
                    self.endpoints.append(endpoint)

        # --- Inline JS endpoint discovery ---
        for script in soup.find_all("script"):
            js_text = script.string or ""
            self._extract_js_endpoints(js_text, base)

        # --- Follow links (same domain only) ---
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(base, href)
            parsed_link = urlparse(full_url)

            # Only follow same-domain links, skip anchors/mailto/etc
            if parsed_link.netloc == self.base_domain and parsed_link.scheme in ("http", "https"):
                clean_url = full_url.split("#")[0]  # remove fragment
                if clean_url not in self.visited:
                    self._crawl_url(clean_url, depth + 1)

    def _process_form(self, form, base_url: str):
        """Extract an Endpoint from a <form> element."""
        action = form.get("action", "")
        method = (form.get("method", "GET") or "GET").upper()
        full_action = urljoin(base_url, action) if action else base_url

        params = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            input_type = inp.get("type", "text").lower()
            if input_type in ("submit", "button", "image", "reset", "hidden"):
                # Still include hidden fields — they can be vulnerable
                if input_type == "hidden":
                    params.append(Param(name=name, location="body",
                                        default_value=inp.get("value", "")))
                continue
            params.append(Param(name=name, location="body" if method == "POST" else "query",
                                default_value=inp.get("value", "")))

        if params:
            endpoint = Endpoint(url=full_action, method=method, params=params)
            self.endpoints.append(endpoint)

    def _extract_js_endpoints(self, js_text: str, base_url: str):
        """Heuristically extract API endpoints from inline JS."""
        for pattern in self.JS_ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, js_text):
                # Get the last group (URL) from the match
                url_candidate = match.group(match.lastindex) if match.lastindex else match.group(1)
                if url_candidate and url_candidate.startswith(("/", "http")):
                    full_url = urljoin(base_url, url_candidate)
                    if urlparse(full_url).netloc == self.base_domain:
                        # Add as a bare endpoint with no known params (will be tested with payloads anyway)
                        endpoint = Endpoint(url=full_url, method="GET", params=[])
                        self.endpoints.append(endpoint)
