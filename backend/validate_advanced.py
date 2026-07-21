"""
DevSecure360 - Phase 1.5 Advanced SAST Validation
Tests: interprocedural taint, new vuln classes, framework detection,
       sanitizer accuracy, field-sensitive taint.
"""
import sys, os, tempfile
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(__file__))

from app.scanner.sast.engine import SASTEngine
engine = SASTEngine()

passed = 0
failed = 0
failures = []

def check(condition, name):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        failures.append(name)
        print(f"  FAIL  {name}")

def scan_code(code: str, suffix=".py") -> list:
    with tempfile.NamedTemporaryFile(suffix=suffix, mode="w", delete=False, encoding="utf-8") as f:
        f.write(code)
        p = f.name
    result = engine.scan(p)
    os.unlink(p)
    return [fi.vuln_class for fi in result.findings]

print("=" * 60)
print("DevSecure360 - Phase 1.5 Advanced SAST Validation")
print("=" * 60)

# ── Test 1: Sanitizer Accuracy (SSA form) ─────────────────────────────────
print("\n[1] Sanitizer Accuracy (SSA prevents false positives)")

safe_sanitized = '''
from flask import request
import sqlite3

def get_user():
    user_id = request.args.get("id")
    safe_id = int(user_id)          # sanitized: x_2 = int(x_1)
    conn = sqlite3.connect("db")
    cur = conn.execute("SELECT * FROM users WHERE id=?", (safe_id,))
    return cur.fetchone()
'''
classes1 = scan_code(safe_sanitized)
check("SQLi" not in classes1, "Sanitized SQLi (parameterized query) -> no false positive")

sql_unsafe = '''
from flask import request
import sqlite3

def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("db")
    cur = conn.execute("SELECT * FROM users WHERE name='" + name + "'")
    return cur.fetchone()
'''
classes1b = scan_code(sql_unsafe)
check("SQLi" in classes1b, "Unsanitized SQLi -> detected")

# ── Test 2: New Vuln Classes ───────────────────────────────────────────────
print("\n[2] New Vulnerability Classes")

xss_code = '''
from flask import request, render_template_string

def render():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")
'''
classes2 = scan_code(xss_code)
check("XSS" in classes2, "XSS: request -> render_template_string detected")

path_trav = '''
from flask import request
import os

def read_file():
    filename = request.args.get("file")
    with open("/var/www/" + filename) as f:
        return f.read()
'''
classes3 = scan_code(path_trav)
check("Path Traversal" in classes3, "Path Traversal: request -> open() detected")

ssrf_code = '''
from flask import request
import requests

def fetch():
    url = request.args.get("url")
    resp = requests.get(url)
    return resp.text
'''
classes4 = scan_code(ssrf_code)
check("SSRF" in classes4, "SSRF: request -> requests.get() detected")

ssti_code = '''
from flask import request, render_template_string

def render():
    tmpl = request.args.get("template")
    return render_template_string(tmpl)
'''
classes5 = scan_code(ssti_code)
check("SSTI" in classes5, "SSTI: request -> render_template_string(user_template) detected")

redirect_code = '''
from flask import request, redirect

def login():
    next_url = request.args.get("next")
    return redirect(next_url)
'''
classes6 = scan_code(redirect_code)
check("Open Redirect" in classes6, "Open Redirect: request -> redirect() detected")

# ── Test 3: Weak Crypto Detection ─────────────────────────────────────────
print("\n[3] Weak Cryptography Pattern Detection")

weak_md5 = '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
'''
classes7 = scan_code(weak_md5)
check("Weak Crypto" in classes7, "Weak Crypto: hashlib.md5() detected")

weak_sha1 = '''
import hashlib

def verify(data):
    return hashlib.sha1(data).hexdigest()
'''
classes7b = scan_code(weak_sha1)
check("Weak Crypto" in classes7b, "Weak Crypto: hashlib.sha1() detected")

safe_crypto = '''
import hashlib

def hash_data(data):
    return hashlib.sha256(data).hexdigest()
'''
classes7c = scan_code(safe_crypto)
check("Weak Crypto" not in classes7c, "Strong Crypto: hashlib.sha256() -> no false positive")

# ── Test 4: Interprocedural Taint ─────────────────────────────────────────
print("\n[4] Interprocedural Taint (cross-function)")

interproc_code = '''
from flask import request
import sqlite3

def get_name():
    return request.args.get("name")  # returns tainted value

def search():
    name = get_name()                # name should be tainted (interprocedural)
    conn = sqlite3.connect("db")
    cur = conn.execute("SELECT * FROM users WHERE name='" + name + "'")
    return cur.fetchone()
'''
classes8 = scan_code(interproc_code)
# Note: interprocedural catches this as CMDi via param seeding, or SQLi via legacy engine
check("SQLi" in classes8, "Interprocedural: taint flows through function return value")

# ── Test 5: Log Injection ─────────────────────────────────────────────────
print("\n[5] Log Injection")

log_inject = '''
from flask import request
import logging

def login():
    username = request.args.get("user")
    logging.info("Login attempt: " + username)
'''
classes9 = scan_code(log_inject)
check("Log Injection" in classes9, "Log Injection: request -> logging.info() detected")

# ── Test 6: Framework Detection ───────────────────────────────────────────
print("\n[6] Framework Detection")

from app.scanner.sast.taint.framework import detect_framework

flask_code = "from flask import Flask, request\napp = Flask(__name__)"
fw = detect_framework(flask_code, "python")
check(fw.name == "flask", f"Flask detected (got: {fw.name})")
check(fw.confidence > 0.5, f"Flask confidence > 0.5 (got: {fw.confidence:.2f})")

django_code = "from django.http import HttpResponse\nfrom django import forms"
fw2 = detect_framework(django_code, "python")
check(fw2.name == "django", f"Django detected (got: {fw2.name})")

fastapi_code = "from fastapi import FastAPI\napp = FastAPI()"
fw3 = detect_framework(fastapi_code, "python")
check(fw3.name == "fastapi", f"FastAPI detected (got: {fw3.name})")

# ── Test 7: Field-Sensitive Taint (dict/object) ────────────────────────────
print("\n[7] Field-Sensitive Taint")

field_taint = '''
from flask import request
import sqlite3

def search():
    params = {}
    params["name"] = request.args.get("name")   # dict field tainted
    query = "SELECT * FROM users WHERE name='" + params["name"] + "'"
    conn = sqlite3.connect("db")
    conn.execute(query)
'''
classes10 = scan_code(field_taint)
check("SQLi" in classes10, "Field-sensitive: dict[key] = source; sink(dict[key]) detected")

# ── Test 8: False Positive Gate ───────────────────────────────────────────
print("\n[8] False Positive Gate (clean code)")

clean = '''
import os
import hashlib

def add(a, b):
    return a + b

def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def greet(name: str) -> str:
    return f"Hello, {name}"

DB_NAME = "myapp.db"

def get_user(user_id: int):
    import sqlite3
    conn = sqlite3.connect(DB_NAME)
    cur = conn.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cur.fetchone()
'''
classes_clean = scan_code(clean)
check(len(classes_clean) == 0, f"Clean file -> zero findings (got {classes_clean})")

# ── Summary ───────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print(f"Results: {passed} passed, {failed} failed")
if failures:
    print("\nFAILED:")
    for f in failures:
        print(f"  - {f}")
    print("\nPhase 1.5 has failures to resolve.")
else:
    print("\nAll advanced checks passed. Phase 1.5 engine is COMPLETE.")
    print("SSA + Dataflow + Interprocedural + Framework Detection active.")
