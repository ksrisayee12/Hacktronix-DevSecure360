import yaml
import os
from pathlib import Path

REQUIRED_FIELDS = [
    "rule_id", "language", "vuln_class", "severity", "cwe",
    "owasp", "cvss_score", "cvss_vector", "confidence",
    "issue", "message", "sources", "sinks", "sanitizers", "remediation"
]

ALLOWED_VULN_CLASSES = {
    "SQLi", "NoSQLi", "CMDi", "XSS", "SSTI", "SSRF", "XXE",
    "Path Traversal", "Open Redirect", "Deserialization", "Code Injection",
    "LDAP Injection", "XPath Injection", "Log Injection", "Hardcoded Secret",
    "Weak Crypto", "JWT Bypass", "Prototype Pollution", "Buffer Overflow",
    "Integer Overflow", "Format String", "Use After Free", "Memory Corruption",
    "Race Condition", "Null Pointer Dereference", "ReDoS", "CSRF",
    "Misconfiguration", "Cookie Security", "File Upload",
    "Mass Assignment", "Out-of-bounds Read"
}

FORBIDDEN_SINKS = {
    "deprecated_function_", "DeprecatedMethod", "vulnerableSink",
    "fake_", "dummy_", "placeholder_", "_vuln", "vuln_func",
    "unsafe_func_", "test_sink_"
}

errors = []
seen_rule_ids = {}

rules_dir = Path("app/scanner/sast/rules")

for f in sorted(rules_dir.rglob("*.yaml")):
    try:
        rule = yaml.safe_load(f.read_text(encoding="utf-8"))
    except Exception as e:
        errors.append(f"PARSE ERROR {f}: {e}")
        continue

    if not rule:
        errors.append(f"EMPTY FILE: {f}")
        continue

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"MISSING FIELD '{field}': {f}")
        elif rule[field] is None or rule[field] == "":
            if field in ["sources", "sinks", "sanitizers"] and isinstance(rule.get(field), list):
                pass # Empty list is allowed for these, but shouldn't be ""
            else:
                errors.append(f"EMPTY FIELD '{field}': {f}")

    # Check rule_id uniqueness
    rid = rule.get("rule_id", "")
    if rid in seen_rule_ids:
        errors.append(f"DUPLICATE rule_id '{rid}': {f} and {seen_rule_ids[rid]}")
    else:
        seen_rule_ids[rid] = f

    # Check vuln_class
    vc = str(rule.get("vuln_class", "")).strip()
    if vc not in ALLOWED_VULN_CLASSES:
        errors.append(f"INVALID vuln_class '{vc}': {f}")

    # Check for fabricated sinks
    sinks = rule.get("sinks", []) or []
    for sink in sinks:
        sink_str = str(sink)
        for forbidden in FORBIDDEN_SINKS:
            if forbidden.lower() in sink_str.lower():
                errors.append(f"FABRICATED SINK '{sink_str}': {f}")

    # Check message is substantial
    msg = str(rule.get("message", ""))
    if len(msg.strip()) < 50:
        errors.append(f"MESSAGE TOO SHORT (<50 chars): {f}")

    # Check remediation is substantial
    rem = str(rule.get("remediation", ""))
    if "validate and sanitize all user input" in rem.lower():
        errors.append(f"USELESS REMEDIATION (copy-paste boilerplate): {f}")
    if len(rem.strip()) < 80:
        errors.append(f"REMEDIATION TOO SHORT (<80 chars): {f}")

    # Check sanitizers are not in sources
    sources = rule.get("sources", []) or []
    sanitizer_patterns = ["escape(", "encode(", "sanitize(", "quote(", "prepare(", "bind"]
    for src in sources:
        for pat in sanitizer_patterns:
            if pat.lower() in str(src).lower():
                errors.append(f"SANITIZER IN SOURCES BLOCK '{src}': {f}")

print(f"Total files checked: {len(list(rules_dir.rglob('*.yaml')))}")
print(f"Total errors: {len(errors)}")
for e in errors:
    print(f"  ERROR: {e}")

if not errors:
    print("ALL RULES PASS VALIDATION")
else:
    print(f"\nFIX ALL {len(errors)} ERRORS BEFORE REPORTING COMPLETION")
    exit(1)
