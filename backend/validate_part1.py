import yaml
from pathlib import Path

ALLOWED_VULN_CLASSES = {
    "SQLi", "NoSQLi", "CMDi", "XSS", "SSTI", "SSRF", "XXE",
    "Path Traversal", "Open Redirect", "Deserialization", "Code Injection",
    "LDAP Injection", "XPath Injection", "Log Injection", "Hardcoded Secret",
    "Weak Crypto", "JWT Bypass", "Prototype Pollution", "Buffer Overflow",
    "Integer Overflow", "Format String", "Use After Free", "Memory Corruption",
    "Race Condition", "Null Pointer Dereference", "ReDoS", "CSRF",
    "Misconfiguration", "Cookie Security", "Mass Assignment",
    "File Upload", "Out-of-bounds Read"
}

ALLOWED_CONFIDENCE = {"Confirmed", "Probable", "Tentative"}
MEMORY_ANALYSIS_RULES = {
    "c_use_after_free", "c_integer_overflow",
    "cpp_integer_overflow", "cpp_out_of_bounds_read"
}

errors = []
for f in sorted(Path("app/scanner/sast/rules").rglob("*.yaml")):
    rule = yaml.safe_load(f.read_text(encoding="utf-8"))
    if not rule:
        errors.append(f"EMPTY: {f}")
        continue
    vc = str(rule.get("vuln_class", "")).strip()
    if vc not in ALLOWED_VULN_CLASSES:
        errors.append(f"INVALID vuln_class '{vc}': {f}")
    conf = str(rule.get("confidence", "")).strip()
    if conf not in ALLOWED_CONFIDENCE:
        errors.append(f"INVALID confidence '{conf}': {f}")
    rid = str(rule.get("rule_id", "")).strip()
    if rid in MEMORY_ANALYSIS_RULES and conf == "Confirmed":
        errors.append(f"MEMORY RULE MUST BE Tentative: {f}")

if errors:
    print(f"PART 1 INCOMPLETE — {len(errors)} errors:")
    for e in errors:
        print(f"  {e}")
else:
    print("PART 1 COMPLETE — all 7 bugs fixed correctly")
