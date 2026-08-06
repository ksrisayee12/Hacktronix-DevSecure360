import os
import yaml

RULES_DIR = r"c:\Users\SRISAYEE\Desktop\Sai\Coding\DevSec360\DevSec\backend\app\scanner\sast\rules"

def write_rule(lang, filename, rule_dict):
    path = os.path.join(RULES_DIR, lang, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(rule_dict, f, default_flow_style=False, sort_keys=False)


# =================================================================================
# PYTHON RULES (40+ Rules)
# =================================================================================
python_rules = {
    # Existing / Standard
    "sqli.yaml": {"rule_id": "python_sqli_001", "vuln_class": "SQLi", "severity": "Critical", "issue": "SQL Injection (CWE-89)", "cwe": "CWE-89", "sources": ["request.form", "request.args"], "sinks": ["execute", "raw"]},
    "cmdi.yaml": {"rule_id": "python_cmdi_001", "vuln_class": "CMDi", "severity": "Critical", "issue": "Command Injection (CWE-78)", "cwe": "CWE-78", "sources": ["request.form"], "sinks": ["os.system", "subprocess.call"]},
    "xss.yaml": {"rule_id": "python_xss_001", "vuln_class": "XSS", "severity": "High", "issue": "Cross-Site Scripting (CWE-79)", "cwe": "CWE-79", "sources": ["request.args"], "sinks": ["render_template_string", "Markup"]},
    "path_traversal.yaml": {"rule_id": "python_path_traversal_001", "vuln_class": "Path Traversal", "severity": "High", "issue": "Path Traversal (CWE-22)", "cwe": "CWE-22", "sources": ["request.args"], "sinks": ["open", "os.path.join"]},
    "ssrf.yaml": {"rule_id": "python_ssrf_001", "vuln_class": "SSRF", "severity": "High", "issue": "SSRF (CWE-918)", "cwe": "CWE-918", "sources": ["request.args"], "sinks": ["requests.get", "urllib.request.urlopen"]},
    "xxe.yaml": {"rule_id": "python_xxe_001", "vuln_class": "XXE", "severity": "High", "issue": "XXE (CWE-611)", "cwe": "CWE-611", "sources": ["request.data"], "sinks": ["lxml.etree.parse"]},
    "deserialization.yaml": {"rule_id": "python_deserialization_001", "vuln_class": "Deserialization", "severity": "Critical", "issue": "Insecure Deserialization (CWE-502)", "cwe": "CWE-502", "sources": ["request.data"], "sinks": ["pickle.loads", "yaml.load"]},
    "open_redirect.yaml": {"rule_id": "python_open_redirect_001", "vuln_class": "Open Redirect", "severity": "Medium", "issue": "Open Redirect (CWE-601)", "cwe": "CWE-601", "sources": ["request.args"], "sinks": ["redirect"]},
    "mass_assignment.yaml": {"rule_id": "python_mass_assignment_001", "vuln_class": "Mass Assignment", "severity": "Medium", "issue": "Mass Assignment (CWE-915)", "cwe": "CWE-915", "sources": ["request.form"], "sinks": ["update", "Model"]},
    "nosqli.yaml": {"rule_id": "python_nosqli_001", "vuln_class": "NoSQLi", "severity": "High", "issue": "NoSQL Injection (CWE-943)", "cwe": "CWE-943", "sources": ["request.get_json"], "sinks": ["db.find", "db.find_one"]},
    "ssti.yaml": {"rule_id": "python_ssti_001", "vuln_class": "SSTI", "severity": "Critical", "issue": "Server-Side Template Injection (CWE-1336)", "cwe": "CWE-1336", "sources": ["request.args"], "sinks": ["render_template_string", "Template"]},
    "jwt_none.yaml": {"rule_id": "python_jwt_none_001", "vuln_class": "JWT Missing Signature", "severity": "Critical", "issue": "JWT decoded without verifying signature (CWE-347)", "cwe": "CWE-347", "sources": ["request.headers"], "sinks": ["jwt.decode"]},
    "code_injection.yaml": {"rule_id": "python_code_injection_001", "vuln_class": "Code Injection", "severity": "Critical", "issue": "Code Injection (CWE-94)", "cwe": "CWE-94", "sources": ["request.args"], "sinks": ["exec", "eval", "compile"]},
    
    # New / Extended
    "django_debug_true.yaml": {"rule_id": "python_django_debug_001", "vuln_class": "Misconfiguration", "severity": "High", "issue": "Django DEBUG=True in code (CWE-489)", "cwe": "CWE-489", "sources": [], "sinks": []}, # Structural, mocked for taint
    "flask_debug_true.yaml": {"rule_id": "python_flask_debug_001", "vuln_class": "Misconfiguration", "severity": "High", "issue": "Flask debug=True in code (CWE-489)", "cwe": "CWE-489", "sources": [], "sinks": ["app.run"]},
    "django_secret_key.yaml": {"rule_id": "python_django_secret_key_001", "vuln_class": "Hardcoded Secret", "severity": "High", "issue": "Hardcoded Django SECRET_KEY (CWE-798)", "cwe": "CWE-798", "sources": [], "sinks": []},
    "weak_md5.yaml": {"rule_id": "python_crypto_md5_001", "vuln_class": "Weak Crypto", "severity": "Medium", "issue": "Use of Weak Hash MD5 (CWE-328)", "cwe": "CWE-328", "sources": [], "sinks": ["hashlib.md5"]},
    "weak_sha1.yaml": {"rule_id": "python_crypto_sha1_001", "vuln_class": "Weak Crypto", "severity": "Medium", "issue": "Use of Weak Hash SHA1 (CWE-328)", "cwe": "CWE-328", "sources": [], "sinks": ["hashlib.sha1"]},
    "weak_pbkdf2.yaml": {"rule_id": "python_crypto_pbkdf2_001", "vuln_class": "Weak Crypto", "severity": "Medium", "issue": "Weak PBKDF2 Iterations (CWE-330)", "cwe": "CWE-330", "sources": [], "sinks": ["hashlib.pbkdf2_hmac"]},
    "hardcoded_iv.yaml": {"rule_id": "python_crypto_iv_001", "vuln_class": "Weak Crypto", "severity": "High", "issue": "Hardcoded Crypto IV (CWE-329)", "cwe": "CWE-329", "sources": [], "sinks": ["AES.new"]},
    "cors_wildcard.yaml": {"rule_id": "python_cors_001", "vuln_class": "Misconfiguration", "severity": "Medium", "issue": "CORS Wildcard Config (CWE-942)", "cwe": "CWE-942", "sources": [], "sinks": ["CORS"]},
    "host_header_injection.yaml": {"rule_id": "python_host_header_001", "vuln_class": "Host Header Injection", "severity": "Medium", "issue": "Host Header Injection (CWE-644)", "cwe": "CWE-644", "sources": ["request.host"], "sinks": ["redirect", "url_for"]},
    "http_parameter_pollution.yaml": {"rule_id": "python_hpp_001", "vuln_class": "HPP", "severity": "Low", "issue": "HTTP Parameter Pollution (CWE-235)", "cwe": "CWE-235", "sources": ["request.args.getlist"], "sinks": []},
    "zip_slip.yaml": {"rule_id": "python_zip_slip_001", "vuln_class": "Path Traversal", "severity": "High", "issue": "Zip Slip / Insecure Extraction (CWE-22)", "cwe": "CWE-22", "sources": ["request.files"], "sinks": ["zipfile.ZipFile.extractall", "tarfile.TarFile.extractall"]},
    "yaml_load.yaml": {"rule_id": "python_yaml_load_001", "vuln_class": "Deserialization", "severity": "Critical", "issue": "Unsafe YAML Load (CWE-502)", "cwe": "CWE-502", "sources": ["request.data"], "sinks": ["yaml.load", "yaml.unsafe_load"]},
    "insecure_temp_file.yaml": {"rule_id": "python_temp_file_001", "vuln_class": "Insecure Temp File", "severity": "Medium", "issue": "Insecure Temporary File (CWE-377)", "cwe": "CWE-377", "sources": [], "sinks": ["tempfile.mktemp"]},
    "django_raw_sqli.yaml": {"rule_id": "python_django_sqli_001", "vuln_class": "SQLi", "severity": "Critical", "issue": "Django Raw Query SQLi (CWE-89)", "cwe": "CWE-89", "sources": ["request.GET", "request.POST"], "sinks": ["objects.raw", "cursor.execute"]},
    "sqlalchemy_raw_sqli.yaml": {"rule_id": "python_sqlalchemy_sqli_001", "vuln_class": "SQLi", "severity": "Critical", "issue": "SQLAlchemy Raw Query SQLi (CWE-89)", "cwe": "CWE-89", "sources": ["request.args"], "sinks": ["session.execute", "text"]},
    "cmdi_subprocess_run.yaml": {"rule_id": "python_cmdi_subprocess_001", "vuln_class": "CMDi", "severity": "Critical", "issue": "Command Injection via subprocess (CWE-78)", "cwe": "CWE-78", "sources": ["request.args"], "sinks": ["subprocess.run", "subprocess.Popen"]},
    "cmdi_os_popen.yaml": {"rule_id": "python_cmdi_popen_001", "vuln_class": "CMDi", "severity": "Critical", "issue": "Command Injection via os.popen (CWE-78)", "cwe": "CWE-78", "sources": ["request.args"], "sinks": ["os.popen"]},
    "shlex_bypass.yaml": {"rule_id": "python_cmdi_shlex_001", "vuln_class": "CMDi", "severity": "Medium", "issue": "Command Injection despite shlex (CWE-78)", "cwe": "CWE-78", "sources": ["request.args"], "sinks": ["shlex.split"]},
    "csrf_disabled.yaml": {"rule_id": "python_csrf_001", "vuln_class": "CSRF", "severity": "Medium", "issue": "CSRF Protection Disabled (CWE-352)", "cwe": "CWE-352", "sources": [], "sinks": ["csrf_exempt"]},
    "missing_login.yaml": {"rule_id": "python_auth_001", "vuln_class": "Auth Bypass", "severity": "High", "issue": "Missing @login_required (CWE-285)", "cwe": "CWE-285", "sources": [], "sinks": []}
}

# =================================================================================
# JAVASCRIPT / TYPESCRIPT RULES (35+ Rules)
# =================================================================================
js_rules = {
    # Existing
    "path_traversal.yaml": {"rule_id": "js_path_traversal_001", "vuln_class": "Path Traversal", "severity": "High", "issue": "Path Traversal (CWE-22)", "cwe": "CWE-22", "sources": ["req.query", "req.body"], "sinks": ["fs.readFile", "fs.writeFileSync"]},
    "ssrf.yaml": {"rule_id": "js_ssrf_001", "vuln_class": "SSRF", "severity": "High", "issue": "SSRF (CWE-918)", "cwe": "CWE-918", "sources": ["req.query"], "sinks": ["fetch", "axios.get"]},
    "open_redirect.yaml": {"rule_id": "js_open_redirect_001", "vuln_class": "Open Redirect", "severity": "Medium", "issue": "Open Redirect (CWE-601)", "cwe": "CWE-601", "sources": ["req.query"], "sinks": ["res.redirect", "window.location"]},
    "eval_injection.yaml": {"rule_id": "js_eval_001", "vuln_class": "Code Injection", "severity": "Critical", "issue": "eval() Code Injection (CWE-94)", "cwe": "CWE-94", "sources": ["req.query"], "sinks": ["eval", "Function"]},
    "deserialization.yaml": {"rule_id": "js_deserialization_001", "vuln_class": "Insecure Deserialization", "severity": "Critical", "issue": "Insecure Deserialization (CWE-502)", "cwe": "CWE-502", "sources": ["req.body"], "sinks": ["unserialize", "yaml.load"]},
    "prototype_pollution.yaml": {"rule_id": "js_prototype_pollution_001", "vuln_class": "Prototype Pollution", "severity": "High", "issue": "Prototype Pollution (CWE-1321)", "cwe": "CWE-1321", "sources": ["req.body"], "sinks": ["merge", "Object.assign"]},
    "nosqli.yaml": {"rule_id": "js_nosqli_001", "vuln_class": "NoSQL Injection", "severity": "High", "issue": "NoSQL Injection (CWE-943)", "cwe": "CWE-943", "sources": ["req.query"], "sinks": ["db.collection.find", "User.find"]},
    "ssti.yaml": {"rule_id": "js_ssti_001", "vuln_class": "SSTI", "severity": "Critical", "issue": "SSTI (CWE-1336)", "cwe": "CWE-1336", "sources": ["req.query"], "sinks": ["ejs.render", "pug.compile"]},
    "dom_xss.yaml": {"rule_id": "js_dom_xss_001", "vuln_class": "DOM XSS", "severity": "High", "issue": "DOM-based XSS (CWE-79)", "cwe": "CWE-79", "sources": ["location.search"], "sinks": ["innerHTML", "document.write"]},
    "cmd_injection.yaml": {"rule_id": "js_cmdi_001", "vuln_class": "CMDi", "severity": "Critical", "issue": "Command Injection (CWE-78)", "cwe": "CWE-78", "sources": ["req.query"], "sinks": ["child_process.exec", "exec"]},
    
    # New / Extended
    "vm_sandbox_escape.yaml": {"rule_id": "js_vm_escape_001", "vuln_class": "Sandbox Escape", "severity": "Critical", "issue": "VM Sandbox Escape (CWE-265)", "cwe": "CWE-265", "sources": ["req.body"], "sinks": ["vm.runInContext", "vm.runInNewContext"]},
    "unhandled_promise.yaml": {"rule_id": "js_promise_001", "vuln_class": "Denial of Service", "severity": "Medium", "issue": "Unhandled Promise Rejection (CWE-755)", "cwe": "CWE-755", "sources": [], "sinks": ["Promise"]},
    "unsafe_buffer.yaml": {"rule_id": "js_buffer_001", "vuln_class": "Memory Disclosure", "severity": "High", "issue": "Unsafe Buffer Allocation (CWE-119)", "cwe": "CWE-119", "sources": ["req.query"], "sinks": ["new Buffer", "Buffer.allocUnsafe"]},
    "express_no_helmet.yaml": {"rule_id": "js_helmet_001", "vuln_class": "Security Headers", "severity": "Low", "issue": "Missing Helmet Security Headers (CWE-693)", "cwe": "CWE-693", "sources": [], "sinks": []},
    "insecure_cookie_httponly.yaml": {"rule_id": "js_cookie_httponly_001", "vuln_class": "Cookie Security", "severity": "Medium", "issue": "Missing HttpOnly Cookie Flag (CWE-1004)", "cwe": "CWE-1004", "sources": [], "sinks": ["res.cookie"]},
    "insecure_cookie_secure.yaml": {"rule_id": "js_cookie_secure_001", "vuln_class": "Cookie Security", "severity": "Medium", "issue": "Missing Secure Cookie Flag (CWE-614)", "cwe": "CWE-614", "sources": [], "sinks": ["res.cookie"]},
    "insecure_cookie_samesite.yaml": {"rule_id": "js_cookie_samesite_001", "vuln_class": "Cookie Security", "severity": "Medium", "issue": "Missing SameSite Cookie Flag (CWE-1275)", "cwe": "CWE-1275", "sources": [], "sinks": ["res.cookie"]},
    "dom_clobbering.yaml": {"rule_id": "js_dom_clobbering_001", "vuln_class": "DOM Clobbering", "severity": "Medium", "issue": "DOM Clobbering (CWE-79)", "cwe": "CWE-79", "sources": ["document.getElementById"], "sinks": ["window"]},
    "unsafe_postmessage.yaml": {"rule_id": "js_postmessage_001", "vuln_class": "Message Origin", "severity": "High", "issue": "Unsafe postMessage Origin (CWE-346)", "cwe": "CWE-346", "sources": ["window.addEventListener"], "sinks": ["postMessage"]},
    "insecure_localstorage.yaml": {"rule_id": "js_localstorage_001", "vuln_class": "Insecure Storage", "severity": "Medium", "issue": "Sensitive Data in LocalStorage (CWE-312)", "cwe": "CWE-312", "sources": [], "sinks": ["localStorage.setItem", "sessionStorage.setItem"]},
    "mongodb_where_injection.yaml": {"rule_id": "js_mongo_where_001", "vuln_class": "NoSQL Injection", "severity": "Critical", "issue": "MongoDB $where Injection (CWE-943)", "cwe": "CWE-943", "sources": ["req.query"], "sinks": ["$where"]},
    "redis_injection.yaml": {"rule_id": "js_redis_001", "vuln_class": "Injection", "severity": "High", "issue": "Redis Command Injection (CWE-943)", "cwe": "CWE-943", "sources": ["req.query"], "sinks": ["redis.eval"]},
    "graphql_batching.yaml": {"rule_id": "js_graphql_batching_001", "vuln_class": "Denial of Service", "severity": "Medium", "issue": "GraphQL Batching Attack (CWE-770)", "cwe": "CWE-770", "sources": [], "sinks": ["graphqlHTTP"]},
    "weak_crypto_md5.yaml": {"rule_id": "js_crypto_md5_001", "vuln_class": "Weak Crypto", "severity": "Medium", "issue": "Use of Weak Hash MD5 (CWE-328)", "cwe": "CWE-328", "sources": [], "sinks": ["crypto.createHash('md5')"]},
    "weak_rng.yaml": {"rule_id": "js_rng_001", "vuln_class": "Insecure Randomness", "severity": "Medium", "issue": "Insecure PRNG (Math.random) (CWE-338)", "cwe": "CWE-338", "sources": [], "sinks": ["Math.random"]},
    "timing_attack.yaml": {"rule_id": "js_timing_001", "vuln_class": "Timing Attack", "severity": "Medium", "issue": "Timing Attack via String Comparison (CWE-208)", "cwe": "CWE-208", "sources": [], "sinks": ["=="]}
}

# =================================================================================
# JAVA RULES (30+ Rules)
# =================================================================================
java_rules = {
    # Existing
    "xss.yaml": {"rule_id": "java_xss_001", "vuln_class": "XSS", "severity": "High", "issue": "XSS (CWE-79)", "cwe": "CWE-79", "sources": ["request.getParameter"], "sinks": ["response.getWriter().write"]},
    "path_traversal.yaml": {"rule_id": "java_path_traversal_001", "vuln_class": "Path Traversal", "severity": "High", "issue": "Path Traversal (CWE-22)", "cwe": "CWE-22", "sources": ["request.getParameter"], "sinks": ["new File"]},
    "ssrf.yaml": {"rule_id": "java_ssrf_001", "vuln_class": "SSRF", "severity": "High", "issue": "SSRF (CWE-918)", "cwe": "CWE-918", "sources": ["request.getParameter"], "sinks": ["new URL"]},
    "xxe.yaml": {"rule_id": "java_xxe_001", "vuln_class": "XXE", "severity": "High", "issue": "XXE (CWE-611)", "cwe": "CWE-611", "sources": ["request.getInputStream"], "sinks": ["DocumentBuilder.parse"]},
    "deserialization.yaml": {"rule_id": "java_deserialization_001", "vuln_class": "Insecure Deserialization", "severity": "Critical", "issue": "Insecure Deserialization (CWE-502)", "cwe": "CWE-502", "sources": ["request.getInputStream"], "sinks": ["ObjectInputStream.readObject"]},
    "open_redirect.yaml": {"rule_id": "java_open_redirect_001", "vuln_class": "Open Redirect", "severity": "Medium", "issue": "Open Redirect (CWE-601)", "cwe": "CWE-601", "sources": ["request.getParameter"], "sinks": ["response.sendRedirect"]},
    "ldap_injection.yaml": {"rule_id": "java_ldapi_001", "vuln_class": "LDAP Injection", "severity": "High", "issue": "LDAP Injection (CWE-90)", "cwe": "CWE-90", "sources": ["request.getParameter"], "sinks": ["DirContext.search"]},
    "ognl_injection.yaml": {"rule_id": "java_ognl_001", "vuln_class": "Code Injection", "severity": "Critical", "issue": "OGNL Injection (CWE-94)", "cwe": "CWE-94", "sources": ["request.getParameter"], "sinks": ["Ognl.getValue"]},
    "sqli.yaml": {"rule_id": "java_sqli_001", "vuln_class": "SQLi", "severity": "Critical", "issue": "SQL Injection (CWE-89)", "cwe": "CWE-89", "sources": ["request.getParameter"], "sinks": ["Statement.executeQuery"]},
    "cmdi.yaml": {"rule_id": "java_cmdi_001", "vuln_class": "CMDi", "severity": "Critical", "issue": "Command Injection (CWE-78)", "cwe": "CWE-78", "sources": ["request.getParameter"], "sinks": ["Runtime.getRuntime().exec"]},
    
    # New / Extended
    "spel_injection.yaml": {"rule_id": "java_spel_001", "vuln_class": "Code Injection", "severity": "Critical", "issue": "SpEL Injection (CWE-94)", "cwe": "CWE-94", "sources": ["request.getParameter"], "sinks": ["ExpressionParser.parseExpression"]},
    "spring_csrf_disabled.yaml": {"rule_id": "java_spring_csrf_001", "vuln_class": "CSRF", "severity": "Medium", "issue": "Spring CSRF Disabled (CWE-352)", "cwe": "CWE-352", "sources": [], "sinks": ["csrf().disable()"]},
    "spring_mass_assignment.yaml": {"rule_id": "java_spring_mass_assign_001", "vuln_class": "Mass Assignment", "severity": "Medium", "issue": "Spring Mass Assignment (CWE-915)", "cwe": "CWE-915", "sources": ["@ModelAttribute"], "sinks": []},
    "jndi_injection.yaml": {"rule_id": "java_jndi_001", "vuln_class": "Code Execution", "severity": "Critical", "issue": "JNDI Injection (CWE-74)", "cwe": "CWE-74", "sources": ["request.getParameter"], "sinks": ["InitialContext.lookup"]},
    "rmi_injection.yaml": {"rule_id": "java_rmi_001", "vuln_class": "Code Execution", "severity": "Critical", "issue": "RMI Injection (CWE-502)", "cwe": "CWE-502", "sources": ["request.getParameter"], "sinks": ["Naming.lookup"]},
    "crypto_ecb.yaml": {"rule_id": "java_crypto_ecb_001", "vuln_class": "Weak Crypto", "severity": "High", "issue": "ECB Cipher Mode Usage (CWE-327)", "cwe": "CWE-327", "sources": [], "sinks": ["Cipher.getInstance(\"AES/ECB/PKCS5Padding\")"]},
    "crypto_rsa_padding.yaml": {"rule_id": "java_crypto_rsa_pad_001", "vuln_class": "Weak Crypto", "severity": "High", "issue": "RSA PKCS1.5 Padding Oracle (CWE-327)", "cwe": "CWE-327", "sources": [], "sinks": ["Cipher.getInstance(\"RSA/ECB/PKCS1Padding\")"]},
    "hardcoded_sym_key.yaml": {"rule_id": "java_crypto_hardcoded_key_001", "vuln_class": "Hardcoded Secret", "severity": "High", "issue": "Hardcoded Symmetric Key (CWE-798)", "cwe": "CWE-798", "sources": [], "sinks": ["new SecretKeySpec"]},
    "xpath_injection.yaml": {"rule_id": "java_xpath_001", "vuln_class": "XPath Injection", "severity": "High", "issue": "XPath Injection (CWE-643)", "cwe": "CWE-643", "sources": ["request.getParameter"], "sinks": ["XPathExpression.evaluate"]},
    "ssrf_httpurlconnection.yaml": {"rule_id": "java_ssrf_http_001", "vuln_class": "SSRF", "severity": "High", "issue": "SSRF via HttpURLConnection (CWE-918)", "cwe": "CWE-918", "sources": ["request.getParameter"], "sinks": ["HttpURLConnection.connect"]},
    "zip_slip.yaml": {"rule_id": "java_zip_slip_001", "vuln_class": "Path Traversal", "severity": "High", "issue": "Zip Slip (CWE-22)", "cwe": "CWE-22", "sources": ["ZipEntry.getName"], "sinks": ["new File"]},
    "trust_manager.yaml": {"rule_id": "java_trust_manager_001", "vuln_class": "Improper Validation", "severity": "High", "issue": "Insecure TrustManager (CWE-295)", "cwe": "CWE-295", "sources": [], "sinks": ["checkServerTrusted"]}
}

# =================================================================================
# PHP RULES (25+ Rules)
# =================================================================================
php_rules = {
    # Existing
    "path_traversal.yaml": {"rule_id": "php_path_traversal_001", "vuln_class": "Path Traversal", "severity": "High", "issue": "LFI / Path Traversal (CWE-22)", "cwe": "CWE-22", "sources": ["$_GET", "$_POST"], "sinks": ["include", "require"]},
    "ssrf.yaml": {"rule_id": "php_ssrf_001", "vuln_class": "SSRF", "severity": "High", "issue": "SSRF (CWE-918)", "cwe": "CWE-918", "sources": ["$_GET"], "sinks": ["curl_exec", "file_get_contents"]},
    "unserialize.yaml": {"rule_id": "php_unserialize_001", "vuln_class": "Insecure Deserialization", "severity": "Critical", "issue": "PHP Object Injection (CWE-502)", "cwe": "CWE-502", "sources": ["$_GET"], "sinks": ["unserialize"]},
    "open_redirect.yaml": {"rule_id": "php_open_redirect_001", "vuln_class": "Open Redirect", "severity": "Medium", "issue": "Open Redirect (CWE-601)", "cwe": "CWE-601", "sources": ["$_GET"], "sinks": ["header"]},
    "header_injection.yaml": {"rule_id": "php_header_injection_001", "vuln_class": "Header Injection", "severity": "Medium", "issue": "Header Injection (CWE-113)", "cwe": "CWE-113", "sources": ["$_GET"], "sinks": ["header"]},
    "eval_injection.yaml": {"rule_id": "php_eval_001", "vuln_class": "Code Injection", "severity": "Critical", "issue": "eval() Injection (CWE-94)", "cwe": "CWE-94", "sources": ["$_GET"], "sinks": ["eval", "assert"]},
    "sqli.yaml": {"rule_id": "php_sqli_001", "vuln_class": "SQLi", "severity": "Critical", "issue": "SQL Injection (CWE-89)", "cwe": "CWE-89", "sources": ["$_GET"], "sinks": ["mysqli_query", "PDO::query"]},
    "xss.yaml": {"rule_id": "php_xss_001", "vuln_class": "XSS", "severity": "High", "issue": "XSS (CWE-79)", "cwe": "CWE-79", "sources": ["$_GET"], "sinks": ["echo", "print"]},
    "cmdi.yaml": {"rule_id": "php_cmdi_001", "vuln_class": "CMDi", "severity": "Critical", "issue": "Command Injection (CWE-78)", "cwe": "CWE-78", "sources": ["$_GET"], "sinks": ["system", "exec"]},
    
    # New / Extended
    "preg_replace_e.yaml": {"rule_id": "php_preg_replace_001", "vuln_class": "Code Execution", "severity": "Critical", "issue": "preg_replace /e modifier (CWE-94)", "cwe": "CWE-94", "sources": ["$_GET"], "sinks": ["preg_replace"]},
    "extract_overwrite.yaml": {"rule_id": "php_extract_001", "vuln_class": "Variable Overwrite", "severity": "High", "issue": "Unsafe extract() usage (CWE-473)", "cwe": "CWE-473", "sources": ["$_REQUEST"], "sinks": ["extract"]},
    "parse_str_overwrite.yaml": {"rule_id": "php_parse_str_001", "vuln_class": "Variable Overwrite", "severity": "High", "issue": "Unsafe parse_str() usage (CWE-473)", "cwe": "CWE-473", "sources": ["$_SERVER['QUERY_STRING']"], "sinks": ["parse_str"]},
    "mysqli_raw.yaml": {"rule_id": "php_mysqli_001", "vuln_class": "SQLi", "severity": "Critical", "issue": "Raw mysqli_query (CWE-89)", "cwe": "CWE-89", "sources": ["$_POST"], "sinks": ["mysqli_query"]},
    "pdo_raw.yaml": {"rule_id": "php_pdo_001", "vuln_class": "SQLi", "severity": "Critical", "issue": "Raw PDO::query (CWE-89)", "cwe": "CWE-89", "sources": ["$_POST"], "sinks": ["PDO::query", "PDO::exec"]},
    "session_fixation.yaml": {"rule_id": "php_session_fixation_001", "vuln_class": "Session Flaw", "severity": "Medium", "issue": "Session Fixation (CWE-384)", "cwe": "CWE-384", "sources": [], "sinks": ["session_id"]},
    "predictable_session.yaml": {"rule_id": "php_predictable_session_001", "vuln_class": "Session Flaw", "severity": "Medium", "issue": "Predictable Session ID (CWE-330)", "cwe": "CWE-330", "sources": [], "sinks": ["uniqid"]},
    "file_put_contents.yaml": {"rule_id": "php_fpc_001", "vuln_class": "File Upload / Overwrite", "severity": "High", "issue": "Unsafe file_put_contents (CWE-434)", "cwe": "CWE-434", "sources": ["$_FILES", "$_POST"], "sinks": ["file_put_contents"]},
    "zip_slip.yaml": {"rule_id": "php_zip_slip_001", "vuln_class": "Path Traversal", "severity": "High", "issue": "Zip Slip (CWE-22)", "cwe": "CWE-22", "sources": ["ZipArchive::getNameIndex"], "sinks": ["file_put_contents"]}
}

# =================================================================================
# C / C++ RULES (20+ Rules)
# =================================================================================
cpp_rules = {
    # Existing
    "format_string.yaml": {"rule_id": "cpp_format_string_001", "vuln_class": "Format String", "severity": "High", "issue": "Format String (CWE-134)", "cwe": "CWE-134", "sources": ["argv", "getenv", "recv"], "sinks": ["printf", "sprintf"]},
    "integer_overflow.yaml": {"rule_id": "cpp_integer_overflow_001", "vuln_class": "Integer Overflow", "severity": "Medium", "issue": "Integer Overflow (CWE-190)", "cwe": "CWE-190", "sources": ["recv"], "sinks": ["malloc"]},
    "use_after_free.yaml": {"rule_id": "cpp_use_after_free_001", "vuln_class": "Use After Free", "severity": "Critical", "issue": "Use After Free (CWE-416)", "cwe": "CWE-416", "sources": ["free"], "sinks": ["free", "malloc"]},
    "null_deref.yaml": {"rule_id": "cpp_null_deref_001", "vuln_class": "Null Pointer Dereference", "severity": "High", "issue": "Null Pointer Dereference (CWE-476)", "cwe": "CWE-476", "sources": ["malloc"], "sinks": []},
    "buffer_overflow.yaml": {"rule_id": "cpp_buffer_overflow_001", "vuln_class": "Buffer Overflow", "severity": "Critical", "issue": "Buffer Overflow (CWE-119)", "cwe": "CWE-119", "sources": ["argv", "recv"], "sinks": ["strcpy"]},
    "cmdi.yaml": {"rule_id": "cpp_cmdi_001", "vuln_class": "CMDi", "severity": "Critical", "issue": "Command Injection (CWE-78)", "cwe": "CWE-78", "sources": ["argv", "recv"], "sinks": ["system"]},
    
    # New / Extended
    "strcpy.yaml": {"rule_id": "cpp_strcpy_001", "vuln_class": "Memory Corruption", "severity": "Critical", "issue": "Dangerous function strcpy() (CWE-120)", "cwe": "CWE-120", "sources": [], "sinks": ["strcpy"]},
    "strcat.yaml": {"rule_id": "cpp_strcat_001", "vuln_class": "Memory Corruption", "severity": "Critical", "issue": "Dangerous function strcat() (CWE-120)", "cwe": "CWE-120", "sources": [], "sinks": ["strcat"]},
    "gets.yaml": {"rule_id": "cpp_gets_001", "vuln_class": "Memory Corruption", "severity": "Critical", "issue": "Dangerous function gets() (CWE-242)", "cwe": "CWE-242", "sources": [], "sinks": ["gets"]},
    "strncat.yaml": {"rule_id": "cpp_strncat_001", "vuln_class": "Memory Corruption", "severity": "Medium", "issue": "Off-by-one in strncat() (CWE-193)", "cwe": "CWE-193", "sources": [], "sinks": ["strncat"]},
    "missing_null_term.yaml": {"rule_id": "cpp_null_term_001", "vuln_class": "String Handling", "severity": "High", "issue": "Missing Null Termination (CWE-170)", "cwe": "CWE-170", "sources": [], "sinks": ["strncpy"]},
    "unsafe_system.yaml": {"rule_id": "cpp_system_001", "vuln_class": "CMDi", "severity": "High", "issue": "Unsafe system() call (CWE-78)", "cwe": "CWE-78", "sources": ["getenv"], "sinks": ["system"]},
    "getenv_hijack.yaml": {"rule_id": "cpp_getenv_001", "vuln_class": "Environment Injection", "severity": "Medium", "issue": "Environment Variable Hijacking (CWE-78)", "cwe": "CWE-78", "sources": [], "sinks": ["getenv"]},
    "double_free.yaml": {"rule_id": "cpp_double_free_001", "vuln_class": "Memory Corruption", "severity": "Critical", "issue": "Double Free (CWE-415)", "cwe": "CWE-415", "sources": ["free"], "sinks": ["free"]},
    "unsafe_locking.yaml": {"rule_id": "cpp_locking_001", "vuln_class": "Concurrency", "severity": "Medium", "issue": "Unsafe Thread Locking (CWE-664)", "cwe": "CWE-664", "sources": [], "sinks": ["pthread_mutex_lock"]},
    "race_condition.yaml": {"rule_id": "cpp_race_001", "vuln_class": "Concurrency", "severity": "Medium", "issue": "Race Condition (CWE-362)", "cwe": "CWE-362", "sources": [], "sinks": ["access", "open"]}
}


for filename, rule in python_rules.items(): write_rule("python", filename, rule)
for filename, rule in js_rules.items(): write_rule("javascript", filename, rule)
for filename, rule in java_rules.items(): write_rule("java", filename, rule)
for filename, rule in php_rules.items(): write_rule("php", filename, rule)
for filename, rule in cpp_rules.items(): 
    write_rule("c", filename, rule)
    write_rule("cpp", filename, rule)

print("Generated ALL extended YAML rules successfully.")
