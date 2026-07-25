from rule_writer import write_rule

GO_SOURCES = [
    "http.Request", "r.URL.Query().Get(", "r.FormValue(", "r.PostFormValue(",
    "r.Header.Get(", "r.Cookie(", "r.Body", "os.Getenv(", "os.Args["
]

CSHARP_SOURCES = [
    "Request.QueryString[", "Request.Form[", "Request.Cookies[", "Request.Headers[",
    "Request.Params[", "Request.Item[", "HttpContext.Request.Query[", "HttpContext.Request.Form[",
    "Environment.GetEnvironmentVariable(", "Environment.GetCommandLineArgs("
]

def gen_go_csharp_rules():
    # Go Rules
    write_rule(
        "go", "go_sqli_database_sql", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via string concatenation in database/sql",
        "User-controlled data is concatenated directly into SQL queries using database/sql methods. An attacker can inject SQL syntax to bypass authentication or access unauthorized data.",
        GO_SOURCES,
        ["db.Query(", "db.QueryRow(", "db.Exec(", "db.QueryContext(", "db.QueryRowContext(", "db.ExecContext(", "tx.Query(", "tx.QueryRow(", "tx.Exec("],
        [],
        "Use parameterized queries with placeholders (?) instead of string concatenation. The database driver safely escapes the parameters.\n\nUNSAFE:\n  db.Query(\"SELECT * FROM users WHERE name='\" + name + \"'\")\n\nSAFE:\n  db.Query(\"SELECT * FROM users WHERE name=?\", name)"
    )

    write_rule(
        "go", "go_sqli_gorm", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via raw queries in GORM",
        "User-controlled data is passed to GORM methods using raw string concatenation. An attacker can manipulate the underlying SQL query.",
        GO_SOURCES,
        ["db.Raw(", "db.Where(", "db.Exec(", "db.First("],
        ["db.Prepare("],
        "Use GORM's built-in parameterization instead of concatenating strings into raw queries or Where clauses.\n\nUNSAFE:\n  db.Where(\"name = '\" + name + \"'\").Find(&users)\n\nSAFE:\n  db.Where(\"name = ?\", name).Find(&users)"
    )

    write_rule(
        "go", "go_cmdi_exec", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via os/exec",
        "User input is passed to os/exec.Command or exec.CommandContext. If input is passed to a shell (e.g., 'sh -c'), an attacker can execute arbitrary OS commands.",
        GO_SOURCES,
        ["exec.Command(", "exec.CommandContext("],
        [],
        "Pass arguments as separate strings to exec.Command rather than routing them through a shell like 'sh' or 'bash'.\n\nUNSAFE:\n  exec.Command(\"sh\", \"-c\", \"ping -c 1 \" + ip)\n\nSAFE:\n  exec.Command(\"ping\", \"-c\", \"1\", ip)"
    )

    write_rule(
        "go", "go_xss_template", "XSS", "High", "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Cross-Site Scripting via text/template or Fprintf",
        "User input is rendered using text/template or fmt.Fprintf directly to the HTTP response. Because text/template does not auto-escape HTML, an attacker can inject malicious scripts.",
        GO_SOURCES,
        ["template.HTML(", "template.JS(", "template.URL(", "template.CSS(", "fmt.Fprintf(w,"],
        ["html/template", "template.HTMLEscapeString(", "template.JSEscapeString("],
        "Always use the html/template package instead of text/template for HTML output, as it provides contextual auto-escaping.\n\nUNSAFE:\n  fmt.Fprintf(w, \"<h1>Hello %s</h1>\", r.FormValue(\"name\"))\n\nSAFE:\n  t, _ := template.New(\"foo\").Parse(\"<h1>Hello {{.Name}}</h1>\")\n  t.Execute(w, data)"
    )

    write_rule(
        "go", "go_ssrf_http", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "Confirmed",
        "Server-Side Request Forgery via net/http",
        "User input is used to construct a URL fetched by the server. An attacker can force the server to issue requests to internal networks or metadata endpoints.",
        GO_SOURCES,
        ["http.Get(", "http.Post(", "http.Head(", "http.NewRequest(", "client.Get(", "client.Do(", "client.Post("],
        [],
        "Validate requested URLs against a strict allowlist. Do not allow users to specify arbitrary URLs for the application to fetch.\n\nUNSAFE:\n  resp, err := http.Get(r.FormValue(\"url\"))\n\nSAFE:\n  // Validate the URL host against an allowlist before calling http.Get"
    )

    write_rule(
        "go", "go_path_traversal", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via os/ioutil",
        "User input dictates the file path in file operations. Attackers can inject traversal sequences to access unauthorized files outside the intended directory.",
        GO_SOURCES,
        ["os.Open(", "os.Create(", "os.ReadFile(", "os.WriteFile(", "ioutil.ReadFile(", "ioutil.WriteFile(", "http.ServeFile(", "http.Dir("],
        ["filepath.Base(", "filepath.Clean("],
        "Use filepath.Base() to extract only the filename from user input, ensuring they cannot traverse directories.\n\nUNSAFE:\n  os.ReadFile(\"/uploads/\" + r.FormValue(\"file\"))\n\nSAFE:\n  filename := filepath.Base(r.FormValue(\"file\"))\n  os.ReadFile(filepath.Join(\"/uploads/\", filename))"
    )

    write_rule(
        "go", "go_weak_crypto", "Weak Crypto", "Medium", "CWE-328", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Use of Weak Cryptographic Algorithms (MD5/SHA1/DES)",
        "The application uses weak cryptographic hash functions like MD5, SHA1, or DES, or insecure random number generators from math/rand.",
        [],
        ["md5.New(", "sha1.New(", "des.NewCipher(", "rc4.NewCipher(", "rand.Int(", "rand.Float64("],
        ["sha256.New(", "sha512.New(", "crypto/rand", "rand.Reader"],
        "Use modern algorithms like SHA-256 (crypto/sha256). For cryptographic randomness, use crypto/rand instead of math/rand.\n\nUNSAFE:\n  h := md5.New()\n\nSAFE:\n  h := sha256.New()"
    )
    
    write_rule(
        "go", "go_hardcoded_secret", "Hardcoded Secret", "High", "CWE-798", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Hardcoded Secret or Credential",
        "The application contains hardcoded secrets (API keys, passwords, tokens) in the source code. If the code is leaked, the secrets can be abused.",
        [],
        [],
        [],
        "Remove hardcoded secrets from source code. Load credentials dynamically from environment variables or a secure configuration system.\n\nUNSAFE:\n  apiKey := \"sk-12345abcdef\"\n\nSAFE:\n  apiKey := os.Getenv(\"API_KEY\")"
    )


    write_rule(
        "go", "go_open_redirect", "Open Redirect", "Medium", "CWE-601", "A01:2021-Broken Access Control", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Open Redirect via http.Redirect()",
        "User input controls the destination URL of an HTTP redirect. Attackers can construct links that redirect users to malicious websites.",
        GO_SOURCES,
        ["http.Redirect("],
        [],
        "Validate redirect URLs against a strict allowlist of permitted destinations.\n\nUNSAFE:\n  http.Redirect(w, r, r.FormValue(\"next\"), 302)\n\nSAFE:\n  // Validate r.FormValue(\"next\") is a safe, relative path before redirecting"
    )

    write_rule(
        "go", "go_ldap_injection", "LDAP Injection", "High", "CWE-90", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "LDAP Injection via unsanitized input in go-ldap Search",
        "User input is passed directly to LDAP search functions without escaping. An attacker can manipulate the LDAP query to bypass authentication or access unauthorized directory information.",
        GO_SOURCES,
        ["l.Search(", "conn.Search("],
        ["ldap.EscapeFilter("],
        "Escape all user-supplied input before using it in LDAP queries using the ldap.EscapeFilter() function. See OWASP LDAP Injection Prevention Cheat Sheet for complete guidance.\n\nUNSAFE:\n  searchRequest := ldap.NewSearchRequest(..., fmt.Sprintf(\"(cn=%s)\", userInput), ...)\n\nSAFE:\n  searchRequest := ldap.NewSearchRequest(..., fmt.Sprintf(\"(cn=%s)\", ldap.EscapeFilter(userInput)), ...)",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/90.html\n# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/go/semmle/go/security/LdapInjection.qll\n# Semgrep Source:  https://semgrep.dev/r/go.lang.security.ldap-injection\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html\n# Verification:    l.Search() and conn.Search() from github.com/go-ldap/ldap execute LDAP queries and require ldap.EscapeFilter() for safety."
    )

    write_rule(
        "go", "go_csrf", "CSRF", "High", "CWE-352", "A01:2021-Broken Access Control", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "Tentative",
        "Cross-Site Request Forgery (CSRF)",
        "The application may not implement CSRF protections. State-changing HTTP handlers registered without CSRF middleware (gorilla/csrf or nosurf) are vulnerable to cross-site request forgery. Note: this rule uses heuristic detection and requires manual review to confirm the absence of CSRF middleware. It will flag all route handlers; verify each finding manually.",
        [],
        ["http.HandleFunc(", "http.Handle(", "router.Handle(", "router.HandleFunc("],
        ["gorilla/csrf", "nosurf"],
        "Implement CSRF protection by requiring unpredictable tokens on state-changing requests, using established middleware like gorilla/csrf.\n\nUNSAFE:\n  http.HandleFunc(\"/update\", updateHandler)\n\nSAFE:\n  // Wrap handler with CSRF middleware"
    )


    # C# Rules
    write_rule(
        "csharp", "csharp_sqli_sqlcommand", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via SqlCommand",
        "User-controlled data is concatenated into a SQL command string. Attackers can inject SQL syntax to bypass authentication or access unauthorized data.",
        CSHARP_SOURCES,
        ["new SqlCommand(", "SqlCommand(", ".ExecuteReader(", ".ExecuteNonQuery(", ".ExecuteScalar(", ".ExecuteReaderAsync(", ".ExecuteNonQueryAsync(", "new NpgsqlCommand(", "MySqlCommand("],
        ["SqlParameter(", "cmd.Parameters.Add(", "cmd.Parameters.AddWithValue("],
        "Use parameterized queries with SqlParameter instead of string concatenation. The database driver safely escapes the parameters.\n\nUNSAFE:\n  var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = '\" + name + \"'\");\n\nSAFE:\n  var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = @name\");\n  cmd.Parameters.AddWithValue(\"@name\", name);"
    )

    write_rule(
        "csharp", "csharp_sqli_ef", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via Entity Framework raw SQL",
        "User-controlled data is passed to Entity Framework methods using raw string concatenation.",
        CSHARP_SOURCES,
        [".ExecuteSqlRaw(", ".ExecuteSqlRawAsync(", ".FromSqlRaw(", "DbContext.Database.ExecuteSqlRaw("],
        [".ExecuteSqlInterpolated(", ".FromSqlInterpolated(", "FromSql("],
        "Use parameterized SQL methods in EF Core like FromSqlInterpolated or ExecuteSqlInterpolated which automatically parameterize interpolated strings.\n\nUNSAFE:\n  ctx.Users.FromSqlRaw(\"SELECT * FROM Users WHERE Name = '\" + name + \"'\");\n\nSAFE:\n  ctx.Users.FromSqlInterpolated($\"SELECT * FROM Users WHERE Name = {name}\");"
    )

    write_rule(
        "csharp", "csharp_cmdi_process", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via Process.Start",
        "User input is passed to Process.Start or ProcessStartInfo. Attackers can execute arbitrary OS commands.",
        CSHARP_SOURCES,
        ["Process.Start(", "new ProcessStartInfo(", "ProcessStartInfo(", "System.Diagnostics.Process.Start("],
        [],
        "Do not pass user input to Process.Start. If you must, pass arguments safely via the Arguments property of ProcessStartInfo rather than concatenating them into the file name.\n\nUNSAFE:\n  Process.Start(\"cmd.exe\", \"/c ping \" + ip);\n\nSAFE:\n  // Validate IP and pass it in ProcessStartInfo.Arguments"
    )

    write_rule(
        "csharp", "csharp_xss_response", "XSS", "High", "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Cross-Site Scripting via unescaped output",
        "User input is written directly to the HTTP response without HTML encoding. Attackers can inject malicious scripts.",
        CSHARP_SOURCES,
        ["Response.Write(", "Response.WriteAsync(", "HttpContext.Response.WriteAsync(", "@Html.Raw(", "Html.Raw(", "MvcHtmlString.Create(", "HtmlHelper.Raw("],
        ["HttpUtility.HtmlEncode(", "WebUtility.HtmlEncode(", "HtmlEncoder.Default.Encode("],
        "Always HTML-encode user input before rendering it in the response, or use Razor views which auto-escape by default.\n\nUNSAFE:\n  Response.Write(\"<h1>Hello \" + name + \"</h1>\");\n\nSAFE:\n  Response.Write(\"<h1>Hello \" + HttpUtility.HtmlEncode(name) + \"</h1>\");"
    )

    write_rule(
        "csharp", "csharp_path_traversal", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via System.IO",
        "User input dictates the file path used in System.IO operations. Attackers can use traversal sequences ('../') to read or write files outside the intended directory.",
        CSHARP_SOURCES,
        ["File.ReadAllText(", "File.WriteAllText(", "File.Open(", "File.Create(", "File.ReadAllBytes(", "new FileStream(", "new StreamReader(", "new StreamWriter("],
        ["Path.GetFileName(", "Path.GetFullPath("],
        "Use Path.GetFileName() to extract only the filename from user input, preventing directory traversal.\n\nUNSAFE:\n  File.ReadAllText(\"/uploads/\" + Request.QueryString[\"file\"]);\n\nSAFE:\n  var filename = Path.GetFileName(Request.QueryString[\"file\"]);\n  File.ReadAllText(Path.Combine(\"/uploads/\", filename));"
    )

    write_rule(
        "csharp", "csharp_deser_binaryformatter", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via BinaryFormatter",
        "Untrusted data is deserialized using BinaryFormatter or related classes. Attackers can execute arbitrary code upon deserialization.",
        CSHARP_SOURCES,
        ["BinaryFormatter.Deserialize(", "new BinaryFormatter(", "LosFormatter.Deserialize(", "ObjectStateFormatter.Deserialize(", "NetDataContractSerializer.Deserialize("],
        [],
        "Do not use BinaryFormatter for deserialization; it is obsolete and inherently insecure. Use JsonSerializer or JsonConvert.\n\nUNSAFE:\n  var formatter = new BinaryFormatter();\n  formatter.Deserialize(stream);\n\nSAFE:\n  JsonSerializer.Deserialize<MyClass>(stream);"
    )

    write_rule(
        "csharp", "csharp_deser_jsonnet", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via TypeNameHandling",
        "Untrusted data is deserialized using JsonConvert with TypeNameHandling enabled. Attackers can execute arbitrary code by supplying malicious type information.",
        CSHARP_SOURCES,
        ["JsonConvert.DeserializeObject("],
        ["JsonConvert.DeserializeObject<KnownType>(", "JsonSerializer.Deserialize<KnownType>("],
        "Do not use TypeNameHandling.All or TypeNameHandling.Auto when deserializing untrusted JSON. Deserialize into concrete, known types.\n\nUNSAFE:\n  var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n  JsonConvert.DeserializeObject(json, settings);\n\nSAFE:\n  JsonConvert.DeserializeObject<MySafeClass>(json);"
    )

    write_rule(
        "csharp", "csharp_xxe_xmldoc", "XXE", "High", "CWE-611", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "XML External Entity (XXE) Injection",
        "User-supplied XML is parsed by an XML parser that has not explicitly disabled external entity resolution (prior to .NET 4.5.2).",
        CSHARP_SOURCES,
        ["new XmlDocument(", "new XmlTextReader(", "XDocument.Load(", "XElement.Load(", "XmlReader.Create("],
        ["XmlReaderSettings DtdProcessing = DtdProcessing.Prohibit"],
        "Explicitly disable DTD processing in XmlReaderSettings when parsing untrusted XML.\n\nUNSAFE:\n  var doc = new XmlDocument();\n  doc.LoadXml(xml);\n\nSAFE:\n  var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };\n  using (var reader = XmlReader.Create(new StringReader(xml), settings)) {\n      var doc = new XmlDocument();\n      doc.Load(reader);\n  }"
    )

    write_rule(
        "csharp", "csharp_ssrf_httpclient", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "Confirmed",
        "Server-Side Request Forgery via HttpClient",
        "User input constructs a URL that the server requests. Attackers can scan internal networks or access internal services.",
        CSHARP_SOURCES,
        ["new HttpClient(", "HttpClient.GetAsync(", "HttpClient.PostAsync(", "HttpClient.SendAsync(", "WebClient.DownloadString(", "WebRequest.Create("],
        [],
        "Validate requested URLs against a strict allowlist. Do not allow users to specify arbitrary URLs to fetch.\n\nUNSAFE:\n  var client = new HttpClient();\n  var response = await client.GetAsync(url);\n\nSAFE:\n  // Validate url against an allowlist before making the request"
    )

    write_rule(
        "csharp", "csharp_weak_crypto", "Weak Crypto", "Medium", "CWE-328", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Use of Weak Cryptographic Algorithms (MD5/SHA1/DES)",
        "The application uses weak cryptographic algorithms (MD5, SHA1, DES) or insecure random number generators (System.Random).",
        [],
        ["new MD5CryptoServiceProvider(", "MD5.Create(", "SHA1.Create(", "new SHA1CryptoServiceProvider(", "DES.Create(", "RC2.Create(", "new Random("],
        ["SHA256.Create(", "SHA512.Create(", "RandomNumberGenerator.Create(", "RandomNumberGenerator.GetBytes("],
        "Use modern algorithms like SHA-256 or AES. For cryptographic randomness, use RandomNumberGenerator instead of System.Random.\n\nUNSAFE:\n  using (var md5 = MD5.Create())\n\nSAFE:\n  using (var sha256 = SHA256.Create())"
    )

    write_rule(
        "csharp", "csharp_open_redirect", "Open Redirect", "Medium", "CWE-601", "A01:2021-Broken Access Control", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Open Redirect via Response.Redirect",
        "User input controls the destination of an HTTP redirect. Attackers can construct links that redirect users to malicious websites, facilitating phishing campaigns.",
        CSHARP_SOURCES,
        ["Response.Redirect(", "Redirect(", "RedirectPermanent(", "RedirectPreserveMethod("],
        ["Url.IsLocalUrl("],
        "Validate redirect URLs against an allowlist, or use Url.IsLocalUrl() to ensure the URL is a relative path to prevent redirecting to external domains.\n\nUNSAFE:\n  return Redirect(Request.QueryString[\"next\"]);\n\nSAFE:\n  if (Url.IsLocalUrl(Request.QueryString[\"next\"])) return Redirect(Request.QueryString[\"next\"]);"
    )

    write_rule(
        "csharp", "csharp_ldap_injection", "LDAP Injection", "High", "CWE-90", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "LDAP Injection via DirectorySearcher",
        "User input is used to dynamically construct LDAP search filters. Attackers can inject special characters to bypass authentication or extract unauthorized information.",
        CSHARP_SOURCES,
        ["new DirectorySearcher(", ".Filter ="],
        ["AntiXssEncoder.XmlAttributeEncode(", "AntiXssEncoder.HtmlEncode("],
        "Escape LDAP special characters (*, (, ), \\, \x00) before including user input in LDAP queries. The AntiXssLibrary provides LDAP encoding methods.\n\nUNSAFE:\n  searcher.Filter = \"(uid=\" + username + \")\";\n\nSAFE:\n  // Properly escape username using a dedicated LDAP encoder"
    )

if __name__ == '__main__':
    gen_go_csharp_rules()
