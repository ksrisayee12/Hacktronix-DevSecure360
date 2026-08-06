"""
DevSecure360 — DAST SPA Crawler
=================================
Uses Playwright headless Chromium for JavaScript-rendered pages (SPAs).
Intercepts XHR/fetch requests and discovers dynamically-added forms.
Falls back gracefully if Playwright is not installed.
"""

import logging
from urllib.parse import urlparse
from app.scanner.dast.crawler.html_crawler import Endpoint, Param

logger = logging.getLogger(__name__)


class SPACrawler:
    """
    Headless browser crawler using Playwright for JS-rendered apps.
    Gracefully falls back if Playwright is unavailable.
    """

    def __init__(self, max_pages: int = 30, timeout_ms: int = 15000):
        self.max_pages = max_pages
        self.timeout_ms = timeout_ms
        self._playwright_available = False
        self._check_playwright()

    def _check_playwright(self):
        try:
            import playwright  # noqa
            self._playwright_available = True
        except ImportError:
            logger.warning("Playwright not installed — SPA crawling disabled. "
                           "Install with: pip install playwright && playwright install chromium")

    def crawl(self, base_url: str) -> list:
        """
        Crawls the base URL using a headless browser.
        Returns list[Endpoint].
        """
        if not self._playwright_available:
            logger.info("SPA crawler skipped (Playwright not available). "
                        "Using HTML crawler results only.")
            return []

        try:
            return self._do_crawl(base_url)
        except Exception as e:
            logger.error(f"SPA crawler failed: {e}. Falling back to HTML crawler only.")
            return []

    def _do_crawl(self, base_url: str) -> list:
        from playwright.sync_api import sync_playwright

        endpoints = []
        visited = set()
        base_domain = urlparse(base_url).netloc
        intercepted_requests = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="DevSecure360-DAST/1.0 (Security Scanner)"
            )
            page = context.new_page()

            # Intercept network requests to discover API calls
            def _on_request(request):
                url = request.url
                method = request.method
                if urlparse(url).netloc == base_domain:
                    intercepted_requests.append({
                        "url": url,
                        "method": method,
                        "post_data": request.post_data,
                    })

            page.on("request", _on_request)

            # Navigate to base URL
            try:
                page.goto(base_url, timeout=self.timeout_ms, wait_until="networkidle")
            except Exception:
                page.goto(base_url, timeout=self.timeout_ms, wait_until="load")

            visited.add(base_url)

            # Find and click navigation links
            links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            for link in links:
                if urlparse(link).netloc == base_domain and link not in visited:
                    if len(visited) >= self.max_pages:
                        break
                    visited.add(link)
                    try:
                        page.goto(link, timeout=self.timeout_ms, wait_until="networkidle")
                        page.wait_for_timeout(500)  # let XHR fire
                    except Exception:
                        pass

            # Process intercepted API requests as endpoints
            for req in intercepted_requests:
                url = req["url"]
                method = req["method"].upper()
                # Parse any POST body params
                params = []
                if req["post_data"]:
                    from urllib.parse import parse_qs
                    try:
                        body_params = parse_qs(req["post_data"])
                        for name, vals in body_params.items():
                            params.append(Param(name=name, location="body",
                                                default_value=vals[0] if vals else ""))
                    except Exception:
                        pass
                endpoint = Endpoint(url=url, method=method, params=params)
                if endpoint not in endpoints:
                    endpoints.append(endpoint)

            browser.close()

        return endpoints
