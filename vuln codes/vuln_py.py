# vuln_python.py — safe, intentionally insecure patterns for testing
import subprocess
import pickle
import os

# 1) shell=True usage (Bandit should flag)
def list_files_bad():
    # safe command but shell=True is insecure; bandit will flag
    subprocess.call("echo 'listing files' && dir", shell=True)

# 2) use of eval on user input (Semgrep/Bandit will flag)
def calculate(expression):
    # insecure: eval on input
    return eval(expression)

# 3) pickle.loads usage on untrusted data (dangerous pattern flagged)
def unsafe_deserialize(s):
    # Do NOT call this with untrusted data in real apps
    return pickle.loads(s)

# 4) hard-coded credential (Semgrep will flag patterns like 'password = "..."')
API_KEY = "hardcoded_api_key_12345"

if __name__ == "__main__":
    print("This file is only for static-analysis testing. Do not run untrusted code.")
