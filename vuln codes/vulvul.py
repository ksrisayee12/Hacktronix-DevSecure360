# ⚠️ Educational Vulnerable File for Scanner Testing Only
# Intentionally insecure – NEVER use in real applications.

import os
import subprocess
import json
import base64

# --- Hardcoded API Key (CWE-798) ---
API_KEY = "ABCD-1234-SECRET-KEY"

# --- Broken Crypto (CWE-327) ---
def insecure_encrypt(data):
    # Base64 is NOT encryption
    return base64.b64encode(data.encode()).decode()

def insecure_decrypt(enc):
    return base64.b64decode(enc.encode()).decode()

# --- Path Traversal (CWE-22) ---
def read_file(filename):
    # No validation: allows "../../etc/passwd"
    with open(filename, "r") as f:
        return f.read()

# --- Unsafe subprocess (CWE-78) ---
def run_command(cmd):
    # Direct shell execution → command injection
    return subprocess.getoutput(cmd)

# --- JSON Injection (CWE-20 / CWE-116) ---
def unsafe_json_parse(raw):
    # Accepts unfiltered JSON strings
    return json.loads(raw)

# --- Fake program flow ---
if __name__ == "__main__":
    print("Insecure encrypted KEY:", insecure_encrypt(API_KEY))

    filename = input("Enter filename to read: ")
    print("\n[File Output]")
    try:
        print(read_file(filename))
    except Exception as e:
        print("Error reading file:", e)

    cmd = input("\nEnter a command to run: ")
    print("[Command Output]")
    print(run_command(cmd))

    raw_json = input("\nEnter JSON data: ")
    try:
        print("Parsed JSON:", unsafe_json_parse(raw_json))
    except:
        print("Invalid JSON")
