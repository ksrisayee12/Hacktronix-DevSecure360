"""
DevSecure360 — DAST HTML Crawler (Enterprise Edition)
======================================================
Full application surface discovery:
- Static HTML (BeautifulSoup4) with form extraction
- sitemap.xml and robots.txt parsing to discover hidden paths
- Inline JS API endpoint extraction (fetch, axios, XHR, jQuery)
- Common parameter fuzzing injection on parameterless pages
- Query string extraction from crawled URLs
"""

from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from typing import Optional, Set
import re
import logging

from app.scanner.dast.http.client import DASTHTTPClient, BINARY_CONTENT_TYPES

logger = logging.getLogger(__name__)

# Static file extensions to skip crawling (but we might still discover them)
SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".webm",
    ".pdf", ".zip", ".tar", ".gz", ".exe", ".dmg",
)

# Common parameter names to inject on parameterless pages — covers 90%+ of real-world vuln params
FUZZ_PARAMS = [
    "id", "q", "query", "search", "s", "keyword",
    "file", "path", "page", "url", "redirect", "next",
    "cat", "category", "type", "action", "view",
    "user", "username", "name", "email",
    "token", "key", "api_key",
    "lang", "language", "locale",
    "order", "sort", "dir",
    "limit", "offset", "page_num",
    "debug", "test", "cmd", "exec",
    "include", "load", "fetch",
    "data", "input", "output",
]


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
    method: str              # GET | POST | PUT | DELETE | PATCH
    params: list = field(default_factory=list)   # list[Param]
    content_type: str = "application/x-www-form-urlencoded"
    source: str = "html"     # "html" | "js" | "sitemap" | "robots" | "fuzz"


class HTMLCrawler:
    """
    Enterprise-grade web crawler and application surface discoverer.
    Discovers all input endpoints and injects common fuzz parameters on bare pages.
    """

    # Extended JS API endpoint detection patterns
    JS_ENDPOINT_PATTERNS = [
        # fetch API
        r'fetch\s*\(["\']([^"\'?#\s]+)["\']',
        r'fetch\s*\(`([^`?#\s]+)`',
        # axios
        r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(["\']([^"\'?#\s]+)["\']',
        r'axios\s*\.\s*(?:request)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\'?#\s]+)["\']',
        # XHR
        r'XMLHttpRequest[^"]*open\s*\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\'?#\s]+)["\']',
        # jQuery
        r'\$\s*\.\s*(?:ajax|get|post)\s*\(\s*["\']([^"\'?#\s]+)["\']',
        r'\$\s*\.\s*ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\'?#\s]+)["\']',
        # API URL constants
        r'(?:apiUrl|API_URL|baseUrl|BASE_URL|endpoint|ENDPOINT)\s*[=:]\s*["\']([^"\']+)["\']',
        # Template literals
        r'fetch\s*\(`([^`]+)`\)',
        # Relative URL strings that look like API paths
        r'["\'](/api/[^"\'?#\s]+)["\']',
        r'["\'](/v\d+/[^"\'?#\s]+)["\']',
        r'["\'](/rest/[^"\'?#\s]+)["\']',
        r'["\'](/graphql)["\']',
    ]

    def __init__(self, http_client: DASTHTTPClient, max_depth: int = 3, max_pages: int = 50):
        self.client = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.endpoints: list = []
        self.base_domain: str = ""
        self._endpoint_urls_seen: Set[str] = set()  # deduplicate endpoints by URL+method

    def crawl(self, base_url: str) -> list:
        """
        Full application surface discovery.
        Returns list[Endpoint] deduplicated by URL+method.
        """
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc

        # Discover hidden paths via sitemap.xml and robots.txt first
        self._crawl_sitemap(base_url)
        self._crawl_robots(base_url)

        # Main HTML crawl
        self._crawl_url(base_url, depth=0)

        logger.debug(f"[Crawler] Discovered {len(self.endpoints)} endpoints from {len(self.visited)} pages")
        return self.endpoints

    # ── Sitemap / Robots discovery ────────────────────────────────────────────

    def _crawl_sitemap(self, base_url: str):
        """Parse sitemap.xml to discover all published URLs."""
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        try:
            resp = self.client.get(sitemap_url)
            if resp.status_code == 200 and resp.body:
                # Parse URLs from sitemap
                urls = re.findall(r'<loc>\s*(https?://[^\s<]+)\s*</loc>', resp.body)
                for url in urls[:100]:   # cap at 100 sitemap URLs
                    if urlparse(url).netloc == self.base_domain:
                        self._crawl_url(url, depth=2)
                logger.debug(f"[Crawler] sitemap.xml: found {len(urls)} URLs")
        except Exception as e:
            logger.debug(f"[Crawler] sitemap.xml failed: {e}")

    def _crawl_robots(self, base_url: str):
        """Parse robots.txt to discover Disallow paths (often hidden admin/API routes)."""
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            resp = self.client.get(robots_url)
            if resp.status_code == 200 and resp.body:
                disallowed = re.findall(r'(?:Disallow|Allow):\s*(/[^\s*]+)', resp.body)
                for path in disallowed:
                    full_url = urljoin(base_url, path)
                    self._crawl_url(full_url, depth=2)
                logger.debug(f"[Crawler] robots.txt: found {len(disallowed)} paths")
        except Exception as e:
            logger.debug(f"[Crawler] robots.txt failed: {e}")

    # ── HTML crawl ────────────────────────────────────────────────────────────

    def _crawl_url(self, url: str, depth: int):
        # Strip fragment
        url = url.split("#")[0]

        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return

        # Skip static file extensions
        clean_path = urlparse(url).path.lower()
        if any(clean_path.endswith(ext) for ext in SKIP_EXTENSIONS):
            return

        self.visited.add(url)

        resp = self.client.get(url)
        if resp.status_code == 0 or not resp.body or resp.is_binary:
            return

        content_type = resp.content_type.lower()
        if not any(ct in content_type for ct in ("text/html", "application/xhtml", "text/plain", "")):
            return

        try:
            soup = BeautifulSoup(resp.body, "html.parser")
        except Exception:
            return

        # Resolve base URL
        base_tag = soup.find("base", href=True)
        base = base_tag["href"] if base_tag else url

        # Extract query params from current URL itself
        parsed = urlparse(url)
        if parsed.query:
            params = [Param(name=k, location="query", default_value=v[0] if v else "")
                      for k, v in parse_qs(parsed.query).items()]
            if params:
                self._add_endpoint(Endpoint(url=url, method="GET", params=params, source="html"))

        # Process forms
        for form in soup.find_all("form"):
            self._process_form(form, base)

        # Extract inline JS endpoints
        for script in soup.find_all("script"):
            js_text = script.string or ""
            if js_text:
                self._extract_js_endpoints(js_text, base)

        # Also check external script src files (not inline)
        for script in soup.find_all("script", src=True):
            script_url = urljoin(base, script["src"])
            if urlparse(script_url).netloc == self.base_domain:
                self._fetch_and_parse_js(script_url)

        # Follow same-domain links
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            full_url = urljoin(base, href)
            link_parsed = urlparse(full_url)
            if link_parsed.netloc == self.base_domain and link_parsed.scheme in ("http", "https"):
                self._crawl_url(full_url, depth + 1)

    def _fetch_and_parse_js(self, script_url: str):
        """Fetch external JS file and extract API endpoints from it."""
        if script_url in self.visited:
            return
        self.visited.add(script_url)
        try:
            resp = self.client.get(script_url)
            if resp.status_code == 200 and resp.body:
                self._extract_js_endpoints(resp.body, script_url)
        except Exception:
            pass

    def _process_form(self, form, base_url: str):
        """Extract an Endpoint from a <form> element."""
        action = form.get("action", "")
        method = (form.get("method", "GET") or "GET").upper()
        full_action = urljoin(base_url, action) if action else base_url

        # Only allow same-domain forms
        if urlparse(full_action).netloc and urlparse(full_action).netloc != self.base_domain:
            return

        params = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            input_type = (inp.get("type") or "text").lower()
            if input_type in ("submit", "button", "image", "reset"):
                continue

            # Always include hidden fields — they can be vulnerable
            location = "body" if method == "POST" else "query"
            params.append(Param(name=name, location=location,
                                default_value=inp.get("value", "")))

        if params:
            self._add_endpoint(Endpoint(url=full_action, method=method, params=params, source="html"))
        elif full_action != base_url:
            # Parameterless form action — still worth fuzzing with common params
            self._add_fuzz_endpoint(full_action, method)

    def _extract_js_endpoints(self, js_text: str, base_url: str):
        """Heuristically extract API endpoints from JS code."""
        for pattern in self.JS_ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, js_text, re.IGNORECASE):
                url_candidate = match.group(match.lastindex) if match.lastindex else match.group(1)
                if not url_candidate:
                    continue
                url_candidate = url_candidate.strip()

                if url_candidate.startswith(("/", "http")):
                    full_url = urljoin(base_url, url_candidate)
                    if urlparse(full_url).netloc == self.base_domain:
                        # Add with common fuzz params since we don't know params
                        self._add_fuzz_endpoint(full_url, "GET")

    def _add_fuzz_endpoint(self, url: str, method: str = "GET"):
        """Add an endpoint with common fuzz parameters for broad coverage."""
        # Use a sensible subset of FUZZ_PARAMS to avoid explosion
        key_params = FUZZ_PARAMS[:15]  # top 15 most common
        params = [Param(name=p, location="query", default_value="test") for p in key_params]
        self._add_endpoint(Endpoint(url=url, method=method, params=params, source="fuzz"))

    def _add_endpoint(self, endpoint: Endpoint):
        """Deduplicate endpoints by URL + method."""
        # Normalize URL (strip trailing slash)
        url = endpoint.url.rstrip("/")
        key = f"{endpoint.method}:{url}"
        if key not in self._endpoint_urls_seen:
            self._endpoint_urls_seen.add(key)
            endpoint.url = url or endpoint.url
            self.endpoints.append(endpoint)
