from rule_writer import write_rule

JS_SOURCES = [
    "req.query.", "req.query[", "req.body.", "req.body[", "req.params.", "req.params[",
    "req.headers[", "req.cookies.", "req.cookies[", "req.get(",
    "request.query.", "request.body.", "request.params.", "request.headers[",
    "process.env.", "process.argv[", "readline.question("
]

def gen_js_rules():
    write_rule(
        "javascript", "js_sqli", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via unparameterized queries",
        "User-controlled data flows into a database query without being parameterized. An attacker can manipulate the query structure to bypass authentication, access unauthorized data, or modify/delete records.",
        JS_SOURCES,
        ["connection.query(", "pool.query(", "db.query(", "client.query(", "sequelize.query(", "knex.raw(", "knex.whereRaw(", ".query("],
        [],
        "Use parameterized queries provided by the database driver or ORM. Never concatenate user input directly into SQL strings.\n\nUNSAFE:\n  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)\n\nSAFE:\n  db.query('SELECT * FROM users WHERE id = ?', [req.query.id])"
    )

    write_rule(
        "javascript", "js_nosqli", "NoSQLi", "High", "CWE-943", "A03:2021-Injection", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "Confirmed",
        "NoSQL Injection via unsanitized input objects",
        "User input is passed directly to NoSQL query methods (like MongoDB's find). If the input is an object containing query operators (e.g., {$ne: null}), attackers can bypass authentication or extract data they shouldn't access.",
        JS_SOURCES,
        ["collection.find(", "collection.findOne(", "collection.update(", "collection.updateOne(", "collection.deleteOne(", "Model.find(", "Model.findOne(", "Model.findById(", "Model.where("],
        [],
        "Sanitize inputs by casting them to strings, or enforce schema validation to ensure inputs are strings and not objects containing NoSQL operators.\n\nUNSAFE:\n  User.find({ username: req.body.username })\n\nSAFE:\n  User.find({ username: String(req.body.username) })"
    )

    write_rule(
        "javascript", "js_cmdi", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via child_process functions",
        "User input is executed as an operating system command through child_process.exec() or similar functions. Attackers can append malicious commands (e.g., using ';' or '&&') to gain full Remote Code Execution on the server.",
        JS_SOURCES,
        ["child_process.exec(", "child_process.execSync(", "child_process.spawn(", "child_process.spawnSync(", "child_process.execFile(", "exec(", "execSync(", "spawn("],
        [],
        "Avoid using exec() and use execFile() or spawn() instead, passing arguments as an array so they are not evaluated by a shell.\n\nUNSAFE:\n  exec('ping -c 1 ' + req.query.ip)\n\nSAFE:\n  execFile('ping', ['-c', '1', req.query.ip])"
    )

    write_rule(
        "javascript", "js_xss", "XSS", "High", "CWE-79", "A03:2021-Injection", 7.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Reflected Cross-Site Scripting (XSS) via unsanitized response writing",
        "User input is directly written to the HTTP response without HTML sanitization or contextual encoding. Attackers can execute arbitrary JavaScript in the victim's browser.",
        JS_SOURCES,
        ["res.send(", "res.write(", "res.json(", "document.write(", "document.writeln(", "innerHTML", "outerHTML"],
        ["DOMPurify.sanitize(", "escapeHTML("],
        "Always sanitize user input before reflecting it in HTML responses, or use safe sinks like textContent. See OWASP XSS Prevention Cheat Sheet for complete guidance.\n\nUNSAFE:\n  res.send('<h1>Hello ' + req.query.name + '</h1>');\n\nSAFE:\n  res.send('<h1>Hello ' + escapeHTML(req.query.name) + '</h1>');"
    )

    write_rule(
        "javascript", "js_csrf", "CSRF", "High", "CWE-352", "A01:2021-Broken Access Control", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "Tentative",
        "Cross-Site Request Forgery via Express route without CSRF middleware",
        "The application may not implement CSRF protections. State-changing HTTP handlers (e.g., app.post, router.put) registered without CSRF middleware (like csurf or its modern replacements) are vulnerable to cross-site request forgery. Note: this rule uses heuristic detection.",
        [],
        ["app.post(", "app.put(", "app.delete(", "app.patch(", "router.post(", "router.put(", "router.delete(", "router.patch("],
        ["csurf", "csrf()", "csrfProtection"],
        "Implement CSRF protection by requiring unpredictable tokens on state-changing requests, using established middleware. See OWASP Cross-Site Request Forgery Prevention Cheat Sheet for complete guidance.\n\nUNSAFE:\n  app.post('/transfer', (req, res) => { ... })\n\nSAFE:\n  app.post('/transfer', csrfProtection, (req, res) => { ... })",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/352.html\n# CodeQL Source:   Not applicable — pattern-based rule\n# Semgrep Source:  https://semgrep.dev/r/javascript.express.security.csurf-disabled\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html\n# Verification:    State-changing express routes without CSRF middleware are a common vulnerable pattern."
    )

    write_rule(
        "javascript", "js_redos", "ReDoS", "High", "CWE-1333", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "Tentative",
        "Regular Expression Denial of Service (ReDoS) via RegExp",
        "A potentially catastrophic regular expression contains nested quantifiers or overlapping alternatives. If evaluated against a crafted long input string, it can cause the regex engine to backtrack exponentially, consuming all CPU resources.",
        [],
        ["new RegExp(", ".match(", ".search(", ".replace("],
        [],
        "Avoid nested quantifiers like (a+)+ or overlapping alternatives like (a|a)+ in regular expressions. See OWASP Regular Expression Denial of Service Prevention Cheat Sheet for complete guidance.\n\nUNSAFE:\n  const regex = new RegExp('^(a+)+$');\n\nSAFE:\n  // Use a simpler, non-backtracking regex or limit input length",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/1333.html\n# CodeQL Source:   Not applicable — pattern-based rule\n# Semgrep Source:  https://semgrep.dev/r/javascript.lang.security.audit.catastrophic-backtracking\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Regular_Expression_Denial_of_Service_Prevention_Cheat_Sheet.html\n# Verification:    RegExp evaluation and string matching functions execute regular expressions and can be vulnerable to catastrophic backtracking."
    )

    write_rule(
        "javascript", "js_path_traversal", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via fs operations",
        "User input controls the file path used in file system operations. Attackers can use traversal sequences ('../') to read or write files outside the intended directory, potentially exposing source code or credentials.",
        JS_SOURCES,
        ["fs.readFile(", "fs.readFileSync(", "fs.writeFile(", "fs.writeFileSync(", "fs.createReadStream(", "fs.createWriteStream(", "fs.open(", "path.join(", "path.resolve(", "require("],
        ["path.basename(", "path.normalize("],
        "Validate file paths to ensure they reside within the expected directory. Use path.basename() if only a filename is expected.\n\nUNSAFE:\n  fs.readFile('/uploads/' + req.query.file)\n\nSAFE:\n  const filename = path.basename(req.query.file)\n  fs.readFile(path.join('/uploads', filename))"
    )

    write_rule(
        "javascript", "js_ssrf", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "Confirmed",
        "Server-Side Request Forgery via HTTP clients",
        "User input constructs a URL that the server requests. Attackers can scan internal networks, access internal services (like AWS metadata), or bypass firewalls.",
        JS_SOURCES,
        ["http.get(", "http.request(", "https.get(", "https.request(", "axios.get(", "axios.post(", "axios.request(", "fetch(", "node-fetch(", "got(", "request(", "superagent.get("],
        [],
        "Validate requested URLs against a strict allowlist of allowed hostnames. Do not allow users to specify arbitrary URLs to fetch.\n\nUNSAFE:\n  axios.get(req.query.url)\n\nSAFE:\n  if (ALLOWED_URLS.includes(req.query.url)) { axios.get(req.query.url); }"
    )

    write_rule(
        "javascript", "js_prototype_pollution", "Prototype Pollution", "High", "CWE-1321", "A08:2021-Software and Data Integrity Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", "Confirmed",
        "Prototype Pollution via recursive merge",
        "User input is merged into objects without preventing modifications to Object.prototype. Attackers can pollute the prototype chain, leading to logic bypasses, DoS, or even RCE if the polluted property is later evaluated.",
        JS_SOURCES,
        ["Object.assign(", "_.merge(", "_.extend(", "_.defaultsDeep(", "jQuery.extend(", "merge(", "extend("],
        [],
        "Use safe object merging functions that explicitly block the '__proto__' or 'constructor' keys, or create objects without prototypes using Object.create(null).\n\nUNSAFE:\n  _.merge(target, req.body)\n\nSAFE:\n  // Validate input schema or use a secure merge library that drops __proto__"
    )

    write_rule(
        "javascript", "js_code_injection", "Code Injection", "Critical", "CWE-94", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Code Injection via eval or Function",
        "User input is executed as JavaScript code via eval(), new Function(), or related mechanisms. This gives an attacker full Remote Code Execution (RCE) in the Node.js environment.",
        JS_SOURCES,
        ["eval(", "new Function(", "vm.runInNewContext(", "vm.runInThisContext(", "vm.Script(", "Function(", "setTimeout(", "setInterval("],
        [],
        "Never pass user input into eval() or new Function(). Use JSON.parse() if parsing serialized data, and safe sandboxing alternatives if code execution is strictly required.\n\nUNSAFE:\n  eval('console.log(' + req.query.msg + ')')\n\nSAFE:\n  console.log(req.query.msg)"
    )

    write_rule(
        "javascript", "js_open_redirect", "Open Redirect", "Medium", "CWE-601", "A01:2021-Broken Access Control", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Open Redirect via res.redirect",
        "User input controls the destination of an HTTP redirect. Attackers can construct links that redirect users to malicious websites, facilitating phishing campaigns.",
        JS_SOURCES,
        ["res.redirect(", "reply.redirect("],
        [],
        "Validate redirect URLs against an allowlist, or ensure the URL is a relative path to prevent redirecting to external domains.\n\nUNSAFE:\n  res.redirect(req.query.next)\n\nSAFE:\n  if (req.query.next.startsWith('/')) res.redirect(req.query.next)"
    )

    write_rule(
        "javascript", "js_weak_crypto", "Weak Crypto", "Medium", "CWE-328", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Use of Weak Cryptographic Algorithms",
        "The application uses weak cryptographic algorithms like MD5 or SHA1, or insecure random number generators like Math.random(). These can be easily compromised by modern attackers.",
        [],
        ["crypto.createHash('md5'", "crypto.createHash('sha1'", "crypto.createCipher('des'", "crypto.createCipher('rc4'", "Math.random("],
        ["crypto.createHash('sha256'", "crypto.createHash('sha512'", "crypto.randomBytes(", "crypto.randomFillSync("],
        "Use modern algorithms like SHA-256 or AES-GCM. For cryptographic randomness, use crypto.randomBytes() instead of Math.random().\n\nUNSAFE:\n  crypto.createHash('md5')\n\nSAFE:\n  crypto.createHash('sha256')"
    )

    write_rule(
        "javascript", "js_cookie_security", "Cookie Security", "Medium", "CWE-614", "A05:2021-Security Misconfiguration", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "Confirmed",
        "Insecure Cookie Configuration",
        "Cookies are set without the Secure or HttpOnly flags. This allows them to be intercepted over unencrypted HTTP connections or accessed via XSS attacks, leading to session hijacking.",
        [],
        ["res.cookie("],
        [],
        "Set the secure, httpOnly, and sameSite flags when configuring cookies to protect them from theft and CSRF.\n\nUNSAFE:\n  res.cookie('session', token)\n\nSAFE:\n  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'Strict' })"
    )

    write_rule(
        "javascript", "js_jwt_bypass", "JWT Bypass", "High", "CWE-287", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "JWT Verification Bypass or None Algorithm",
        "The application decodes JWTs without verifying the signature or allows the 'none' algorithm. Attackers can forge tokens and impersonate any user.",
        [],
        ["jwt.decode(", "jsonwebtoken.decode("],
        ["jwt.verify(", "jsonwebtoken.verify("],
        "Always use jwt.verify() to check the token signature instead of jwt.decode(). Explicitly define the allowed algorithms to prevent 'none' algorithm attacks.\n\nUNSAFE:\n  const payload = jwt.decode(token)\n\nSAFE:\n  const payload = jwt.verify(token, secret, { algorithms: ['HS256'] })"
    )

    write_rule(
        "javascript", "js_ssti", "SSTI", "Critical", "CWE-1336", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Server-Side Template Injection via template engines",
        "User input is passed unsanitized into a template engine rendering function (like Pug, EJS, Handlebars). Attackers can inject template directives, which are evaluated by the engine, leading to Server-Side Template Injection and potentially Remote Code Execution.",
        JS_SOURCES,
        ["pug.render(", "pug.compile(", "ejs.render(", "ejs.renderFile(", "handlebars.compile(", "nunjucks.renderString("],
        [],
        "Do not pass user input directly into template strings to be compiled. Always pass user input as context variables so the template engine treats them as data rather than executable code.\n\nUNSAFE:\n  ejs.render('Hello ' + req.query.name)\n\nSAFE:\n  ejs.render('Hello <%= name %>', {name: req.query.name})"
    )

    write_rule(
        "javascript", "js_deserialization_nodeserialize", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via node-serialize",
        "Untrusted data is deserialized using node-serialize (unserialize function) or similar insecure deserializers. Because node-serialize supports immediately invoked function expressions (IIFEs) in serialized objects, attackers can craft payloads that execute arbitrary code upon deserialization.",
        JS_SOURCES,
        ["serialize.unserialize(", "unserialize("],
        [],
        "Never use node-serialize or other insecure deserializers on untrusted data. Use safe, standard data formats like JSON (JSON.parse()) which do not support function execution.\n\nUNSAFE:\n  var obj = serialize.unserialize(req.body.data);\n\nSAFE:\n  var obj = JSON.parse(req.body.data);"
    )

if __name__ == '__main__':
    gen_js_rules()
