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

    _warned_once = False   # class-level flag so warning only prints once per process

    def _check_playwright(self):
        try:
            import playwright  # noqa — verify package is installed first
        except ImportError:
            if not SPACrawler._warned_once:
                logger.warning("Playwright not installed — SPA crawling disabled. "
                               "Install with: pip install playwright && python -m playwright install chromium")
                SPACrawler._warned_once = True
            return

        # Verify the browser binary exists by running a quick subprocess check.
        # We CANNOT call sync_playwright() here — uvicorn's asyncio loop is already
        # running and sync_playwright() will raise "Sync API inside asyncio loop".
        # A subprocess has its own loop and avoids the conflict entirely.
        import subprocess, sys
        check_script = (
            "from playwright.sync_api import sync_playwright;"
            "import os;"
            "with sync_playwright() as p:"
            "    print(os.path.exists(p.chromium.executable_path))"
        )
        try:
            result = subprocess.run(
                [sys.executable, "-c", check_script],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip() == "True":
                self._playwright_available = True
            else:
                raise RuntimeError(result.stderr.strip() or "Browser binary not found")
        except Exception as e:
            if not SPACrawler._warned_once:
                logger.warning(f"Playwright browser not ready — SPA crawling disabled. "
                               f"Run: python -m playwright install chromium  (detail: {e})")
                SPACrawler._warned_once = True

    def crawl(self, base_url: str) -> list:
        """
        Crawls the base URL using a headless browser.
        Returns list[Endpoint].
        Runs in a ThreadPoolExecutor so Playwright's sync API doesn't conflict
        with FastAPI's asyncio event loop.
        """
        if not self._playwright_available:
            logger.info("SPA crawler skipped (Playwright not available). "
                        "Using HTML crawler results only.")
            return []

        try:
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._do_crawl, base_url)
                return future.result(timeout=60)   # 60s hard cap per SPA crawl
        except FuturesTimeout:
            logger.warning("SPA crawler timed out after 60s. Continuing with HTML crawler results.")
            return []
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
