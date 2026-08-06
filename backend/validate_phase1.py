"""
DevSecure360 - Phase 1 SAST Validation Script
Run from the backend/ directory: python validate_phase1.py

All checks must pass before Phase 1 is considered complete.
"""

import sys
import os
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(__file__))

from app.scanner.sast.engine import SASTEngine

engine = SASTEngine()

print("=" * 60)
print("DevSecure360 — Phase 1 SAST Validation")
print("=" * 60)

PASS = []
FAIL = []


def check(condition: bool, name: str):
    if condition:
        PASS.append(name)
        print(f"  PASS  {name}")
    else:
        FAIL.append(name)
        print(f"  FAIL  {name}")


# ── Test 1: vuln_flask.py ────────────────────────────────────────────────────
vuln_flask_path = os.path.join(os.path.dirname(__file__), "..", "vuln codes", "vuln_flask.py")
if not os.path.exists(vuln_flask_path):
    # Try alternate path
    vuln_flask_path = os.path.join(os.path.dirname(__file__), "..", "vuln_codes", "vuln_flask.py")

print(f"\n[1] Scanning vuln_flask.py")
print(f"    Path: {vuln_flask_path}")
result = engine.scan(vuln_flask_path)
classes = [f.vuln_class for f in result.findings]
print(f"    Found: {classes}")

check("SQLi" in classes,             "vuln_flask.py -> SQLi detected")
check("CMDi" in classes,             "vuln_flask.py -> CMDi detected")
check("Hardcoded Secret" in classes, "vuln_flask.py -> Hardcoded Secret detected")

for f in result.findings:
    check(len(f.taint_trace) > 0 or f.vuln_class == "Hardcoded Secret",
          f"vuln_flask.py -> {f.vuln_class} has taint trace")
    check(f.line is not None,        f"vuln_flask.py -> {f.vuln_class} has line number")
    check(f.cwe is not None,         f"vuln_flask.py -> {f.vuln_class} has CWE")

# ── Test 2: vuln_py.py ───────────────────────────────────────────────────────
vuln_py_path = os.path.join(os.path.dirname(__file__), "..", "vuln codes", "vuln_py.py")
if not os.path.exists(vuln_py_path):
    vuln_py_path = os.path.join(os.path.dirname(__file__), "..", "vuln_codes", "vuln_py.py")

print(f"\n[2] Scanning vuln_py.py")
print(f"    Path: {vuln_py_path}")
result2 = engine.scan(vuln_py_path)
classes2 = [f.vuln_class for f in result2.findings]
print(f"    Found: {classes2}")

check("CMDi" in classes2,             "vuln_py.py -> CMDi (shell=True) detected")
check("Code Injection" in classes2,       "vuln_py.py -> eval() injection detected")
check("Deserialization" in classes2,  "vuln_py.py -> pickle.loads detected")
check("Hardcoded Secret" in classes2, "vuln_py.py -> Hardcoded Secret detected")

# ── Test 3: Clean file (zero false positives) ─────────────────────────────────
print("\n[3] Scanning clean file (expecting zero findings)")
import tempfile
clean_code = '''
import os

def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}"

DB_NAME = "myapp.db"

def get_user(user_id: int):
    import sqlite3
    conn = sqlite3.connect(DB_NAME)
    # Parameterized query — safe
    cur = conn.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cur.fetchone()
'''
with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False, encoding="utf-8") as f:
    f.write(clean_code)
    clean_path = f.name

result3 = engine.scan(clean_path)
os.unlink(clean_path)
check(len(result3.findings) == 0, f"Clean file -> zero findings (got {len(result3.findings)})")

# ── Test 4: ScanResult structure ──────────────────────────────────────────────
print("\n[4] Checking ScanResult structure")
check(result.scan_id is not None,        "ScanResult has scan_id")
check(result.status == "completed",      "ScanResult status is completed")
check(result.started_at is not None,     "ScanResult has started_at")
check(result.completed_at is not None,   "ScanResult has completed_at")
check(isinstance(result.findings, list), "ScanResult.findings is a list")

# ── Test 5: Finding structure ─────────────────────────────────────────────────
print("\n[5] Checking Finding structure on first finding")
if result.findings:
    f = result.findings[0]
    check(f.id is not None,           "Finding has id")
    check(f.rule_id is not None,      "Finding has rule_id")
    check(f.vuln_class is not None,   "Finding has vuln_class")
    check(f.file is not None,         "Finding has file")
    check(f.severity is not None,     "Finding has severity")
    check(f.issue is not None,        "Finding has issue")
    check(f.remediation is not None,  "Finding has remediation")
    check(f.tool == "devsecure_sast", "Finding tool is devsecure_sast")

# ── Test 5b: Go vulnerabilities ──────────────────────────────────────────────
print("\n[5b] Scanning vuln_go.go")
go_path = os.path.join(os.path.dirname(__file__), "vuln_go.go")
result_go = engine.scan(go_path)
classes_go = [f.vuln_class for f in result_go.findings]
check("SQLi" in classes_go, "vuln_go.go -> SQLi detected")
check("CMDi" in classes_go, "vuln_go.go -> CMDi detected")
check("XSS" in classes_go, "vuln_go.go -> XSS detected")
check("Path Traversal" in classes_go, "vuln_go.go -> Path Traversal detected")

# ── Test 5c: C# vulnerabilities ──────────────────────────────────────────────
print("\n[5c] Scanning vuln_csharp.cs")
cs_path = os.path.join(os.path.dirname(__file__), "vuln_csharp.cs")
result_cs = engine.scan(cs_path)
classes_cs = [f.vuln_class for f in result_cs.findings]
check("SQLi" in classes_cs, "vuln_csharp.cs -> SQLi detected")
check("CMDi" in classes_cs, "vuln_csharp.cs -> CMDi detected")
check("XSS" in classes_cs, "vuln_csharp.cs -> XSS detected")
check("Path Traversal" in classes_cs, "vuln_csharp.cs -> Path Traversal detected")

# ── Test 6: Multi-language support ────────────────────────────────────────────
print("\n[6] Checking multi-language parser availability")
from app.scanner.sast.parser.base import supported_extensions, LANGUAGE_MAP
exts = supported_extensions()
check(".py" in exts,   "Python parser available")
check(".js" in exts,   "JavaScript parser available")
check(".java" in exts, "Java parser available")
check(".php" in exts,  "PHP parser available")
check(".c" in exts,    "C parser available")
check(".cpp" in exts,  "C++ parser available")
print(f"    Active extensions: {sorted(exts)}")

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"Results: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print(f"\nFAILED:")
    for name in FAIL:
        print(f"  - {name}")
    print("\nPhase 1 is NOT complete. Fix failures before proceeding.")
    sys.exit(1)
else:
    print("\nAll checks passed. Phase 1 is COMPLETE.")
    print("The engine is wired into main.py and ready for testing via the frontend.")
