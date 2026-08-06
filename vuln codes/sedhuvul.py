# ⚠️ Educational Vulnerable File for Scanner Testing Only
# Contains intentional weaknesses – DO NOT USE IN PRODUCTION

import os
import hashlib
import pickle
import sqlite3

# --- Hardcoded Credentials (CWE-798) ---
USERNAME = "admin"
PASSWORD = "123456"  # weak password

# --- Weak Hashing (CWE-327) ---
def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

# --- SQL Injection (Simulated) (CWE-89) ---
def login(user, pwd):
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE users(username TEXT, password TEXT)")
    c.execute("INSERT INTO users VALUES('admin','123456')")
    
    # Vulnerable query
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
    print("Executing:", query)
    result = c.execute(query).fetchone()

    return result

# --- Command Injection (CWE-78) ---
def ping_host(host):
    # NO sanitization — vulnerable
    os.system(f"ping -c 1 {host}")

# --- Insecure Deserialization (CWE-502) ---
def load_data(blob):
    return pickle.loads(blob)  # unsafe


# --- Program Start ---
if __name__ == "__main__":
    print("Weak hash of PASSWORD:", weak_hash(PASSWORD))

    user = input("Enter username: ")
    pwd = input("Enter password: ")
    print("Login result:", login(user, pwd))

    host = input("Enter host to ping: ")
    ping_host(host)

    bad_blob = pickle.dumps({"msg": "hello"})  # safe example
    print("Loaded data:", load_data(bad_blob))
