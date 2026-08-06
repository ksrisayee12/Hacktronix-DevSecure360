import os
import yaml

RULES_DIR = r"c:\Users\SRISAYEE\Desktop\Sai\Coding\DevSec360\DevSec\backend\app\scanner\sast\rules"

def write_rule(lang, filename, rule_dict):
    path = os.path.join(RULES_DIR, lang, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(rule_dict, f, default_flow_style=False, sort_keys=False)

# --- JAVASCRIPT RULES ---
js_rules = {
    "path_traversal.yaml": {
        "rule_id": "js_path_traversal_001",
        "vuln_class": "Path Traversal",
        "severity": "High",
        "issue": "Path Traversal (CWE-22)",
        "remediation": "Use path.basename() or a strict allowlist. Do not concatenate untrusted strings into file paths.",
        "sources": ["req.query", "req.body", "req.params", "req.headers", "request.url"],
        "sinks": ["fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync", "path.join"]
    },
    "ssrf.yaml": {
        "rule_id": "js_ssrf_001",
        "vuln_class": "SSRF",
        "severity": "High",
        "issue": "Server-Side Request Forgery (CWE-918)",
        "remediation": "Validate URLs against a strict allowlist before making requests. Avoid passing user input directly to HTTP clients.",
        "sources": ["req.query", "req.body", "req.params"],
        "sinks": ["fetch", "axios.get", "axios.post", "http.get", "http.request", "request"]
    },
    "open_redirect.yaml": {
        "rule_id": "js_open_redirect_001",
        "vuln_class": "Open Redirect",
        "severity": "Medium",
        "issue": "Open Redirect (CWE-601)",
        "remediation": "Validate redirect targets against an allowlist. Do not redirect to untrusted URLs.",
        "sources": ["req.query", "req.body"],
        "sinks": ["res.redirect", "window.location", "location.href"]
    },
    "eval_injection.yaml": {
        "rule_id": "js_eval_001",
        "vuln_class": "Code Injection",
        "severity": "Critical",
        "issue": "eval() Code Injection (CWE-94)",
        "remediation": "Never use eval() with untrusted input. Parse data using JSON.parse() instead.",
        "sources": ["req.query", "req.body", "req.params"],
        "sinks": ["eval", "Function", "setTimeout", "setInterval"]
    },
    "deserialization.yaml": {
        "rule_id": "js_deserialization_001",
        "vuln_class": "Insecure Deserialization",
        "severity": "Critical",
        "issue": "Insecure Deserialization (CWE-502)",
        "remediation": "Use safe parsing libraries like JSON.parse. Avoid node-serialize or eval-based parsers.",
        "sources": ["req.body", "req.query"],
        "sinks": ["serialize.unserialize", "unserialize", "yaml.load"]
    },
    "prototype_pollution.yaml": {
        "rule_id": "js_prototype_pollution_001",
        "vuln_class": "Prototype Pollution",
        "severity": "High",
        "issue": "Prototype Pollution (CWE-1321)",
        "remediation": "Avoid recursive merges without validating keys (e.g. __proto__). Use Object.create(null) or Map.",
        "sources": ["req.body", "req.query"],
        "sinks": ["merge", "clone", "unsafeExtend", "Object.assign"]
    },
    "nosqli.yaml": {
        "rule_id": "js_nosqli_001",
        "vuln_class": "NoSQL Injection",
        "severity": "High",
        "issue": "NoSQL Injection (CWE-943)",
        "remediation": "Use strongly typed schema models (Mongoose) or cast parameters to string before passing to query operators.",
        "sources": ["req.query", "req.body"],
        "sinks": ["db.collection.find", "User.find", "User.findOne", "Model.update"]
    },
    "ssti.yaml": {
        "rule_id": "js_ssti_001",
        "vuln_class": "SSTI",
        "severity": "Critical",
        "issue": "Server-Side Template Injection (CWE-1336)",
        "remediation": "Use logic-less templates or ensure template engines do not allow code execution. Do not pass untrusted strings as templates.",
        "sources": ["req.query", "req.body"],
        "sinks": ["ejs.render", "pug.compile", "handlebars.compile"]
    },
    "dom_xss.yaml": {
        "rule_id": "js_dom_xss_001",
        "vuln_class": "DOM XSS",
        "severity": "High",
        "issue": "DOM-based XSS (CWE-79)",
        "remediation": "Use innerText or textContent instead of innerHTML. Avoid document.write().",
        "sources": ["location.search", "location.hash", "document.referrer", "window.name"],
        "sinks": ["innerHTML", "document.write", "outerHTML"]
    },
    "cmd_injection.yaml": {
        "rule_id": "js_cmdi_002",
        "vuln_class": "CMDi",
        "severity": "Critical",
        "issue": "Command Injection in child_process (CWE-78)",
        "remediation": "Use child_process.execFile() or child_process.spawn() with arguments array instead of exec().",
        "sources": ["req.query", "req.body"],
        "sinks": ["child_process.exec", "exec", "execSync", "spawn"]
    }
}

for filename, rule in js_rules.items():
    write_rule("javascript", filename, rule)

# --- PYTHON RULES ---
python_rules = {
    "jwt_none.yaml": {
        "rule_id": "python_jwt_none_001",
        "vuln_class": "JWT Missing Signature",
        "severity": "Critical",
        "issue": "JWT decoded without verifying signature (CWE-347)",
        "remediation": "Always pass verify=True and algorithms parameter to jwt.decode().",
        "sources": ["request.headers", "request.cookies", "request.args"],
        "sinks": ["jwt.decode"]
    },
    "xxe.yaml": {
        "rule_id": "python_xxe_001",
        "vuln_class": "XXE",
        "severity": "High",
        "issue": "XML External Entity (XXE) Processing (CWE-611)",
        "remediation": "Use defusedxml or disable resolve_entities in lxml.",
        "sources": ["request.data", "request.form"],
        "sinks": ["lxml.etree.parse", "xml.etree.ElementTree.parse", "xml.dom.minidom.parseString"]
    },
    "nosqli.yaml": {
        "rule_id": "python_nosqli_001",
        "vuln_class": "NoSQL Injection",
        "severity": "High",
        "issue": "NoSQL Injection (CWE-943)",
        "remediation": "Validate input types and avoid passing raw dictionaries from request to MongoDB queries.",
        "sources": ["request.get_json", "request.form", "request.args"],
        "sinks": ["db.find", "db.find_one", "db.update_one", "db.delete_many"]
    },
    "ldapi.yaml": {
        "rule_id": "python_ldapi_001",
        "vuln_class": "LDAP Injection",
        "severity": "High",
        "issue": "LDAP Injection (CWE-90)",
        "remediation": "Use ldap3 escaping functions before constructing LDAP queries.",
        "sources": ["request.args", "request.form"],
        "sinks": ["ldap.search_s", "connection.search"]
    },
    "race_condition.yaml": {
        "rule_id": "python_race_condition_001",
        "vuln_class": "Race Condition",
        "severity": "Medium",
        "issue": "Time-of-check Time-of-use (TOCTOU) Race Condition (CWE-367)",
        "remediation": "Avoid os.path.exists before open. Just try to open and catch FileNotFoundError.",
        "sources": [],  # Often non-taint, structural (handled separately or as taint sink for now)
        "sinks": ["os.path.exists", "os.access"]
    },
    "insecure_random.yaml": {
        "rule_id": "python_insecure_random_001",
        "vuln_class": "Insecure Randomness",
        "severity": "Medium",
        "issue": "Use of Cryptographically Weak PRNG (CWE-338)",
        "remediation": "Use secrets module (secrets.token_hex(), secrets.choice()) for security tokens.",
        "sources": [], 
        "sinks": ["random.random", "random.randint", "random.choice"]
    },
    "mass_assignment.yaml": {
        "rule_id": "python_mass_assignment_001",
        "vuln_class": "Mass Assignment",
        "severity": "Medium",
        "issue": "Mass Assignment / Overposting (CWE-915)",
        "cwe": "CWE-915",
        "remediation": "Explicitly define which fields can be updated. Do not pass **request.form to models.",
        "sources": ["request.form", "request.get_json"],
        "sinks": ["Model", "User", "update"] # Simplified for now
    },
    "code_injection.yaml": {
        "rule_id": "python_code_injection_001",
        "vuln_class": "Code Injection",
        "severity": "Critical",
        "issue": "Code Injection (CWE-94)",
        "cwe": "CWE-94",
        "remediation": "Never use exec(), eval(), or compile() on untrusted input.",
        "sources": ["request.args", "request.form"],
        "sinks": ["exec", "compile", "__import__"]
    }
}

for filename, rule in python_rules.items():
    write_rule("python", filename, rule)

# --- JAVA RULES ---
java_rules = {
    "xss.yaml": {
        "rule_id": "java_xss_001",
        "vuln_class": "XSS",
        "severity": "High",
        "issue": "Cross-Site Scripting (CWE-79)",
        "remediation": "Use context-aware output encoding (e.g., OWASP Java Encoder) before rendering to HTML.",
        "sources": ["request.getParameter", "request.getHeader"],
        "sinks": ["response.getWriter().write", "response.getWriter().print"]
    },
    "path_traversal.yaml": {
        "rule_id": "java_path_traversal_001",
        "vuln_class": "Path Traversal",
        "severity": "High",
        "issue": "Path Traversal (CWE-22)",
        "remediation": "Validate input against a strict allowlist. Use Path.normalize() and check if it starts with the intended directory.",
        "sources": ["request.getParameter"],
        "sinks": ["new File", "Paths.get", "new FileInputStream", "new FileOutputStream"]
    },
    "ssrf.yaml": {
        "rule_id": "java_ssrf_001",
        "vuln_class": "SSRF",
        "severity": "High",
        "issue": "Server-Side Request Forgery (CWE-918)",
        "remediation": "Validate URLs against an allowlist. Avoid making HTTP requests to user-supplied hostnames.",
        "sources": ["request.getParameter"],
        "sinks": ["new URL", "HttpClient.send", "URLConnection.openConnection"]
    },
    "xxe.yaml": {
        "rule_id": "java_xxe_001",
        "vuln_class": "XXE",
        "severity": "High",
        "issue": "XML External Entity (XXE) Processing (CWE-611)",
        "remediation": "Disable DTD processing in DocumentBuilderFactory, SAXParserFactory, and XMLInputFactory.",
        "sources": ["request.getInputStream", "request.getParameter"],
        "sinks": ["DocumentBuilder.parse", "SAXParser.parse", "XMLReader.parse"]
    },
    "deserialization.yaml": {
        "rule_id": "java_deserialization_001",
        "vuln_class": "Insecure Deserialization",
        "severity": "Critical",
        "issue": "Insecure Deserialization (CWE-502)",
        "remediation": "Do not deserialize untrusted data. If required, use a restricted ObjectInputStream with a class allowlist.",
        "sources": ["request.getInputStream", "request.getParameter"],
        "sinks": ["ObjectInputStream.readObject", "XMLDecoder.readObject"]
    },
    "open_redirect.yaml": {
        "rule_id": "java_open_redirect_001",
        "vuln_class": "Open Redirect",
        "severity": "Medium",
        "issue": "Open Redirect (CWE-601)",
        "remediation": "Validate the redirect URL. Do not redirect to untrusted user input.",
        "sources": ["request.getParameter"],
        "sinks": ["response.sendRedirect"]
    },
    "ldap_injection.yaml": {
        "rule_id": "java_ldapi_001",
        "vuln_class": "LDAP Injection",
        "severity": "High",
        "issue": "LDAP Injection (CWE-90)",
        "remediation": "Escape user input before incorporating it into LDAP queries. Use search filters safely.",
        "sources": ["request.getParameter"],
        "sinks": ["DirContext.search", "InitialDirContext.search"]
    },
    "ognl_injection.yaml": {
        "rule_id": "java_ognl_001",
        "vuln_class": "Code Injection",
        "severity": "Critical",
        "issue": "OGNL Injection (CWE-94)",
        "remediation": "Do not evaluate untrusted input as OGNL expressions.",
        "sources": ["request.getParameter"],
        "sinks": ["Ognl.getValue", "ActionContext.getContext().getValueStack().findValue"]
    }
}

for filename, rule in java_rules.items():
    write_rule("java", filename, rule)


# --- PHP RULES ---
php_rules = {
    "path_traversal.yaml": {
        "rule_id": "php_path_traversal_001",
        "vuln_class": "Path Traversal",
        "severity": "High",
        "issue": "Path Traversal / Local File Inclusion (CWE-22)",
        "remediation": "Validate input using a strict allowlist. Use basename() to extract only the filename.",
        "sources": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"],
        "sinks": ["include", "include_once", "require", "require_once", "file_get_contents", "fopen", "readfile"]
    },
    "ssrf.yaml": {
        "rule_id": "php_ssrf_001",
        "vuln_class": "SSRF",
        "severity": "High",
        "issue": "Server-Side Request Forgery (CWE-918)",
        "remediation": "Validate URLs against an allowlist before making requests. Avoid curl to untrusted hostnames.",
        "sources": ["$_GET", "$_POST", "$_REQUEST"],
        "sinks": ["curl_exec", "file_get_contents", "fopen"]
    },
    "unserialize.yaml": {
        "rule_id": "php_unserialize_001",
        "vuln_class": "Insecure Deserialization",
        "severity": "Critical",
        "issue": "PHP Object Injection (CWE-502)",
        "remediation": "Do not use unserialize() with untrusted input. Use json_decode() instead.",
        "sources": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"],
        "sinks": ["unserialize"]
    },
    "open_redirect.yaml": {
        "rule_id": "php_open_redirect_001",
        "vuln_class": "Open Redirect",
        "severity": "Medium",
        "issue": "Open Redirect (CWE-601)",
        "remediation": "Validate redirect targets. Avoid redirecting based purely on user input.",
        "sources": ["$_GET", "$_POST"],
        "sinks": ["header"]
    },
    "header_injection.yaml": {
        "rule_id": "php_header_injection_001",
        "vuln_class": "Header Injection",
        "severity": "Medium",
        "issue": "HTTP Response Splitting / Header Injection (CWE-113)",
        "remediation": "Do not include newline characters in HTTP headers. Validate all input passed to header().",
        "sources": ["$_GET", "$_POST"],
        "sinks": ["header"]
    },
    "eval_injection.yaml": {
        "rule_id": "php_eval_001",
        "vuln_class": "Code Injection",
        "severity": "Critical",
        "issue": "eval() Code Injection (CWE-94)",
        "remediation": "Never use eval() or assert() with untrusted input.",
        "sources": ["$_GET", "$_POST"],
        "sinks": ["eval", "assert", "create_function"]
    }
}

for filename, rule in php_rules.items():
    write_rule("php", filename, rule)


# --- C/C++ RULES ---
cpp_rules = {
    "format_string.yaml": {
        "rule_id": "cpp_format_string_001",
        "vuln_class": "Format String",
        "severity": "High",
        "issue": "Format String Vulnerability (CWE-134)",
        "remediation": "Always use a static format string (e.g., printf(\"%s\", user_input)). Do not pass user input as the format string.",
        "sources": ["argv", "getenv", "recv", "read"],
        "sinks": ["printf", "fprintf", "sprintf", "snprintf", "syslog"]
    },
    "integer_overflow.yaml": {
        "rule_id": "cpp_integer_overflow_001",
        "vuln_class": "Integer Overflow",
        "severity": "Medium",
        "issue": "Integer Overflow (CWE-190)",
        "remediation": "Validate arithmetic bounds before allocating memory or performing critical calculations.",
        "sources": ["argv", "getenv", "recv", "read", "atoi"],
        "sinks": ["malloc", "calloc", "realloc", "new", "memcpy", "strncpy"]
    },
    "use_after_free.yaml": {
        "rule_id": "cpp_use_after_free_001",
        "vuln_class": "Use After Free",
        "severity": "Critical",
        "issue": "Use After Free (CWE-416)",
        "remediation": "Set pointers to NULL immediately after calling free(). Avoid dangling pointers.",
        "sources": ["free"], # Technically CFG based, not standard taint, but we flag for now
        "sinks": ["free", "malloc"] 
    },
    "null_deref.yaml": {
        "rule_id": "cpp_null_deref_001",
        "vuln_class": "Null Pointer Dereference",
        "severity": "High",
        "issue": "Null Pointer Dereference (CWE-476)",
        "remediation": "Check pointers for NULL before dereferencing them.",
        "sources": ["malloc", "calloc"],
        "sinks": [] # Handled by structural checks usually, but placeholder
    }
}

for filename, rule in cpp_rules.items():
    write_rule("c", filename, rule)
    write_rule("cpp", filename, rule)

print("Generated all YAML rules successfully.")
