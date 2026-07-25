from rule_writer import write_rule

PHP_SOURCES = [
    "$_GET[", "$_POST[", "$_REQUEST[", "$_COOKIE[", "$_FILES[", "$_SERVER[",
    "$HTTP_GET_VARS[", "$HTTP_POST_VARS[", "$HTTP_COOKIE_VARS[", "$HTTP_RAW_POST_DATA",
    "file_get_contents('php://input')"
]

def gen_php_rules():
    write_rule(
        "php", "php_sqli", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via unparameterized queries",
        "User-controlled data is concatenated directly into a SQL query string. Attackers can inject SQL commands to bypass authentication or manipulate database records.",
        PHP_SOURCES,
        ["mysqli_query(", "mysql_query(", "pg_query(", "sqlite_query(", "PDO::query(", "PDO::exec(", "$db->query(", "$mysqli->query("],
        ["prepare(", "bindParam(", "bindValue(", "mysqli_real_escape_string(", "pg_escape_string(", "mysqli_stmt_bind_param("],
        "Use prepared statements with parameterized queries (e.g., via PDO or MySQLi). Never concatenate user input directly into SQL strings.\n\nUNSAFE:\n  $db->query(\"SELECT * FROM users WHERE id = \" . $_GET['id']);\n\nSAFE:\n  $stmt = $db->prepare(\"SELECT * FROM users WHERE id = ?\");\n  $stmt->execute([$_GET['id']]);"
    )

    write_rule(
        "php", "php_cmdi", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via exec/system",
        "User input is passed directly to operating system command execution functions. Attackers can append shell commands to gain Remote Code Execution (RCE) on the server.",
        PHP_SOURCES,
        ["exec(", "system(", "shell_exec(", "passthru(", "popen(", "proc_open(", "pcntl_exec(", "` (backticks)"],
        ["escapeshellarg(", "escapeshellcmd("],
        "Avoid using OS command execution functions if possible. If required, strictly sanitize user input using escapeshellarg().\n\nUNSAFE:\n  system(\"ping -c 1 \" . $_POST['ip']);\n\nSAFE:\n  system(\"ping -c 1 \" . escapeshellarg($_POST['ip']));"
    )

    write_rule(
        "php", "php_xss", "XSS", "High", "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Cross-Site Scripting (XSS) via unescaped output",
        "User input is directly echoed back to the browser without escaping. Attackers can inject malicious scripts that execute in the victim's browser context.",
        PHP_SOURCES,
        ["echo ", "print ", "printf(", "vprintf(", "die(", "exit("],
        ["htmlspecialchars(", "htmlentities(", "strip_tags("],
        "Always escape user input using htmlspecialchars() before rendering it in HTML.\n\nUNSAFE:\n  echo \"<h1>Welcome, \" . $_GET['name'] . \"</h1>\";\n\nSAFE:\n  echo \"<h1>Welcome, \" . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . \"</h1>\";"
    )

    write_rule(
        "php", "php_path_traversal", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via file operations",
        "User input dictates the file path used in file operations or inclusion. Attackers can read sensitive files or execute remote code (LFI/RFI).",
        PHP_SOURCES,
        ["include(", "include_once(", "require(", "require_once(", "fopen(", "file_get_contents(", "readfile(", "file(", "unlink("],
        ["basename(", "realpath("],
        "Validate file paths to ensure they reside in the expected directory. Use basename() to extract only the filename from user input.\n\nUNSAFE:\n  include($_GET['page'] . '.php');\n\nSAFE:\n  $page = basename($_GET['page']);\n  include($page . '.php');"
    )

    write_rule(
        "php", "php_ssrf", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "Confirmed",
        "Server-Side Request Forgery via file_get_contents or cURL",
        "User input constructs a URL that the server requests. Attackers can access internal network services or bypass IP allowlists.",
        PHP_SOURCES,
        ["file_get_contents(", "fopen(", "curl_setopt(", "curl_exec("],
        [],
        "Validate requested URLs against a strict allowlist. Do not allow users to specify arbitrary URLs to fetch.\n\nUNSAFE:\n  $data = file_get_contents($_POST['url']);\n\nSAFE:\n  // Validate the URL against an allowlist before fetching"
    )

    write_rule(
        "php", "php_deserialization", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via unserialize",
        "Untrusted data is passed to unserialize(). Attackers can craft malicious serialized PHP objects that execute arbitrary code upon deserialization (via magic methods).",
        PHP_SOURCES,
        ["unserialize("],
        ["json_decode("],
        "Do not use unserialize() for untrusted data. Use safer data formats like JSON and json_decode().\n\nUNSAFE:\n  $data = unserialize($_COOKIE['session']);\n\nSAFE:\n  $data = json_decode($_COOKIE['session'], true);"
    )

    write_rule(
        "php", "php_code_injection", "Code Injection", "Critical", "CWE-94", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Code Injection via eval/assert",
        "User input is passed to eval() or assert(). Attackers can inject arbitrary PHP code, leading to complete Remote Code Execution.",
        PHP_SOURCES,
        ["eval(", "assert(", "create_function(", "preg_replace( (with /e modifier)"],
        [],
        "Never pass user input into eval() or assert(). Refactor the logic to avoid dynamic code evaluation entirely.\n\nUNSAFE:\n  eval(\"return \" . $_GET['math'] . \";\");\n\nSAFE:\n  // Use an explicit math parsing library instead of eval"
    )

    write_rule(
        "php", "php_weak_crypto", "Weak Crypto", "Medium", "CWE-328", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Use of Weak Cryptographic Algorithms (MD5/SHA1)",
        "The application uses weak cryptographic hash functions like MD5 or SHA1, or weak PRNGs like rand() or mt_rand().",
        [],
        ["md5(", "sha1(", "rand(", "mt_rand(", "uniqid(", "mcrypt_encrypt("],
        ["hash('sha256'", "hash('sha512'", "password_hash(", "random_bytes(", "random_int("],
        "Use modern algorithms like SHA-256 for hashing, password_hash() for passwords, and random_bytes() for secure random numbers.\n\nUNSAFE:\n  $hash = md5($password);\n\nSAFE:\n  $hash = password_hash($password, PASSWORD_DEFAULT);"
    )

    write_rule(
        "php", "php_file_upload", "File Upload", "Critical", "CWE-434", "A04:2021-Insecure Design", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Unrestricted File Upload via move_uploaded_file",
        "User-uploaded files are saved without validating their type, extension, or content. Attackers can upload malicious PHP scripts (e.g., shell.php) and execute them on the server, leading to Remote Code Execution.",
        PHP_SOURCES,
        ["move_uploaded_file(", "copy(", "file_put_contents("],
        [],
        "Strictly validate uploaded files. Enforce a strong allowlist for file extensions, verify the MIME type using finfo, limit file size, and store uploaded files outside the web root or without execution permissions.\n\nUNSAFE:\n  move_uploaded_file($_FILES['userfile']['tmp_name'], $upload_dir . $_FILES['userfile']['name']);\n\nSAFE:\n  // Validate extension, MIME type, and use a randomly generated safe filename."
    )

    write_rule(
        "php", "php_mass_assignment", "Mass Assignment", "Medium", "CWE-915", "A01:2021-Broken Access Control", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Confirmed",
        "Mass Assignment via Model::create() or fill()",
        "The application passes user input directly into model creation or update methods without defining fillable or guarded attributes. Attackers can modify unauthorized fields.",
        PHP_SOURCES,
        ["create(", "fill(", "update("],
        ["$fillable", "$guarded", "only("],
        "Define $fillable or $guarded arrays on your Eloquent models to restrict which attributes can be mass assigned. Use the only() method on the request object to explicitly select allowed fields.\n\nUNSAFE:\n  User::create($_POST);\n\nSAFE:\n  User::create($request->only(['username', 'email']));"
    )

    write_rule(
        "php", "php_xxe", "XXE", "High", "CWE-611", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "XML External Entity (XXE) Injection via unsafe XML parser",
        "The application parses XML input using an unsafe configuration. An attacker can include external entities in the XML document, leading to local file disclosure, SSRF, or denial of service.",
        PHP_SOURCES,
        ["simplexml_load_string(", "simplexml_load_file(", "DOMDocument::loadXML(", "DOMDocument::load(", "xml_parse(", "XMLReader::open("],
        ["libxml_disable_entity_loader(true)"],
        "Disable external entity loading before parsing XML data. Note that PHP 8.0+ disables entity loading by default. See OWASP XML External Entity Prevention Cheat Sheet for complete guidance.\n\nUNSAFE:\n  $doc = simplexml_load_string($_POST['xml']);\n\nSAFE:\n  libxml_disable_entity_loader(true);\n  $doc = simplexml_load_string($_POST['xml']);",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/611.html\n# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/php/semmle/php/security/XXE.qll\n# Semgrep Source:  https://semgrep.dev/r/php.lang.security.xxe.xxe\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html\n# Verification:    simplexml_load_string() and DOMDocument::loadXML() are the standard vulnerable PHP XML parsing functions."
    )

    write_rule(
        "php", "php_ldap_injection", "LDAP Injection", "High", "CWE-90", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "LDAP Injection via unsanitized input in LDAP query",
        "User input is passed directly to LDAP search or modification functions without escaping. An attacker can manipulate the LDAP query to bypass authentication or access unauthorized directory information.",
        PHP_SOURCES,
        ["ldap_search(", "ldap_list(", "ldap_read(", "ldap_add(", "ldap_modify(", "ldap_delete("],
        ["ldap_escape("],
        "Escape all user-supplied input before using it in LDAP queries using the ldap_escape() function. See OWASP LDAP Injection Prevention Cheat Sheet for complete guidance.\n\nUNSAFE:\n  $sr = ldap_search($ds, $dn, \"cn=\".$_GET['username']);\n\nSAFE:\n  $sr = ldap_search($ds, $dn, \"cn=\".ldap_escape($_GET['username'], \"\", LDAP_ESCAPE_FILTER));",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/90.html\n# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/php/semmle/php/security/dataflow/LdapInjection.qll\n# Semgrep Source:  https://semgrep.dev/r/php.lang.security.ldap-injection\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html\n# Verification:    ldap_search(), ldap_list(), and ldap_read() execute LDAP queries and require ldap_escape() for safety."
    )

    write_rule(
        "php", "php_open_redirect", "Open Redirect", "Medium", "CWE-601", "A01:2021-Broken Access Control", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Open Redirect via header()",
        "User input controls the destination of an HTTP redirect via the Location header. Attackers can construct links that redirect users to malicious websites, facilitating phishing campaigns.",
        PHP_SOURCES,
        ["header(\"Location:\"", "header('Location:'"],
        [],
        "Validate redirect URLs against an allowlist, or ensure the URL is a relative path to prevent redirecting to external domains.\n\nUNSAFE:\n  header(\"Location: \" . $_GET['redirect_url']);\n\nSAFE:\n  // Validate redirect_url before passing it to header()"
    )

if __name__ == '__main__':
    gen_php_rules()
