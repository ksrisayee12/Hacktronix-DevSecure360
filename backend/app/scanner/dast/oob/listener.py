"""
DevSecure360 — OOB Callback Listener
======================================
Runs a local HTTP server in a background thread.
Captures inbound callbacks from OOB payloads (SSRF, blind CMDi, blind SQLi).
Each payload embeds a unique canary_id; when the listener sees that ID,
the vulnerability is confirmed — proof of blind exploitation.
"""

import threading
import socket
import logging
import time
from typing import Optional
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


class _CallbackHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that captures all inbound requests."""

    def do_GET(self):
        self.server.callbacks[self.path] = {
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers),
            "body": "",
            "received_at": time.time(),
        }
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        self.server.callbacks[self.path] = {
            "method": "POST",
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
            "received_at": time.time(),
        }
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass  # suppress default stdout logging


class _CallbackServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.callbacks: dict = {}   # path -> callback data


class OOBListener:
    """
    OOB (Out-of-Band) HTTP listener for blind vulnerability confirmation.

    Usage:
        listener = OOBListener(host="0.0.0.0", port=4444)
        listener.start()

        canary = listener.generate_canary("ssrf")
        payload_url = listener.canary_url(canary)
        # inject payload_url into target

        result = listener.get_callback(canary, timeout=10)
        if result:
            print("Blind SSRF confirmed! Evidence:", result)

        listener.stop()

    NOTE: For production/deployed use, set OOB_HOST to a public-facing domain
    (e.g. oob.devsecure360.io) so target servers can reach it.
    For localhost testing, the target must be on the same machine.

    TODO: Wire DNS listener to a managed DNS zone for full blind SQLi/SSRF OOB coverage.
    This stub covers HTTP-based OOB callbacks (sufficient for SSRF, blind CMDi).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 4444):
        self.host = host
        self.port = port
        self._server: Optional[_CallbackServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """Start the OOB listener in a background thread."""
        try:
            self._server = _CallbackServer((self.host, self.port), _CallbackHandler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            self._running = True
            logger.info(f"OOB listener started on http://{self.host}:{self.port}")
        except OSError as e:
            logger.warning(f"OOB listener failed to start on port {self.port}: {e}. "
                           "Blind vulnerability detection will be limited.")
            self._running = False

    def stop(self):
        """Stop the OOB listener."""
        if self._server:
            self._server.shutdown()
            self._running = False

    def generate_canary(self, vuln_class: str) -> str:
        """Generate a unique canary ID for a specific vulnerability class."""
        import uuid
        return f"{vuln_class}-{uuid.uuid4().hex[:12]}"

    def canary_url(self, canary_id: str) -> str:
        """Return the full URL to embed in a payload."""
        return f"http://{self.host}:{self.port}/{canary_id}"

    def get_callback(self, canary_id: str, timeout: float = 10.0) -> Optional[str]:
        """
        Poll for an inbound callback containing canary_id.
        Returns the raw request evidence string if found, else None.
        """
        if not self._running:
            return None

        deadline = time.time() + timeout
        while time.time() < deadline:
            for path, data in list(self._server.callbacks.items()):
                if canary_id in path or canary_id in data.get("body", ""):
                    return (
                        f"OOB callback received!\n"
                        f"Method: {data['method']}\n"
                        f"Path: {data['path']}\n"
                        f"Headers: {data['headers']}\n"
                        f"Body: {data['body']}"
                    )
            time.sleep(0.2)
        return None

    @property
    def is_running(self) -> bool:
        return self._running
