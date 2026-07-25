# DevSecure360 SAST Engine — Strict Ruleset Rebuild
# READ THIS ENTIRE DOCUMENT BEFORE CREATING OR MODIFYING A SINGLE YAML FILE.
# This is not optional. This is not a suggestion. Every rule in this document is an order.

---

## WHY THIS EXISTS — THE AUDIT RESULTS

The current ruleset was fully audited. Here is what was found across all 8 languages:

### Completeness Failures (Missing Required Fields)
```
Python     (224 files): 221 missing owasp | 221 missing message | 26 missing remediation
JavaScript (187 files): 183 missing owasp | 183 missing message | 23 missing remediation
Java       (126 files): 125 missing owasp | 125 missing message | 22 missing remediation
PHP        (104 files): 104 missing owasp | 104 missing message | 16 missing remediation
Go         (109 files): 109 missing owasp | 109 missing message | 109 missing remediation
C#         (108 files): 108 missing owasp | 108 missing message | 108 missing remediation
C           (86 files):  86 missing owasp |  86 missing message | 16 missing remediation
C++         (98 files):  98 missing owasp |  98 missing message | 16 missing remediation
```
942 out of 1,042 rule files are structurally incomplete. This is not acceptable.

### Structural Errors Found in the Rules
The following are not opinions. These are bugs confirmed by code audit:

**1. Sanitizers placed in sources list (Python sqli_001.yaml):**
`'%s'`, `'?'`, `:param`, and `execute` appear in the `sources:` block.
These are sanitizers and sinks — not sources. A source is where user input enters.
A parameterized placeholder `%s` is not a source of user input.

**2. Sources placed in sinks list:**
`urllib.request.urlopen` and `requests.get` appear in the `sinks:` list of Python SSRF rules,
but these same functions also appear in the `sources:` list of other rules.
A function is either a source or a sink — never both. Pick the correct one.

**3. Sinks appearing in sources list (JavaScript — entire vuln class):**
In every JavaScript CMDi rule (cmdi_001.yaml through cmdi_012.yaml) and all
code_injection rules, `req.query` appears inside the `sources:` block.
`req.query` is a source. This is correct. But the audit flag triggered because
`req.query` was appearing alongside items that belong in sinks.
Go through every rule and verify each item is in the correct block.

**4. Sanitizers appearing in sinks list (PHP sqli rules):**
`prepare(`, `bindParam(`, `bindValue(`, and `real_escape_string` appear in the `sinks:`
list of PHP SQLi rules. These are sanitizers, not sinks. A sink is where the
dangerous operation happens. A sanitizer is what makes it safe.

**5. Fabricated rules inflating count:**
- Go: 100 out of 109 files have `vuln_class: Best Practice` with fake sinks
  like `deprecated_function_10(` that do not exist in real Go code.
- C#: 100 out of 108 files have `vuln_class: Best Practice` with fake sinks
  like `DeprecatedMethod10(` that do not exist in real C# code.
These 200 files must be deleted and replaced with real rules.

**6. C and C++ are identical:**
The C and C++ buffer overflow rules have exactly the same sinks, the same sources,
and the same remediation text. C and C++ have meaningful differences:
C++ has STL containers, RAII, string classes, and different safe alternatives.
The rules must reflect the actual language, not be copy-pasted.

**7. Massive duplication within the same vuln class:**
Python has 20 separate SQLi rule files but only 38 unique sink entries total.
That is less than 2 unique sinks per file on average.
Python has 28 separate SSRF rule files for what is essentially one concept.
Each file should cover a distinct sink or framework. Multiple files covering
the same sink in different combinations is noise, not coverage.

**8. Identical source lists pasted across unrelated vuln classes:**
The same 16-item HTTP source list appears in SQLi, SSRF, XSS, Path Traversal,
CMDi, SSTI, Log Injection, and Deserialization rules without any per-vuln adjustment.
Some vulns do not apply to all sources. SSRF requires a URL source — environment
variables do not typically lead to SSRF. Weak Crypto and Hardcoded Secrets have
no HTTP sources at all because they are pattern-based, not taint-based.

---

## THE FOUNDATION RULE — READ THIS FIRST

**Every sink you write must be a real function or method that exists in that
language's standard library, official SDK, or a widely-used production framework.
You must be able to state its package name and explain what it does.**

Before writing any sink, ask yourself:
- Is this a real function in this language?
- What package or module does it belong to?
- Would a developer actually write this in production code?
- Is this function dangerous specifically for this vulnerability class?

If you cannot answer all four — do not write it.

**Every source you write must be a real way that user-controlled data enters
a program in that language. Ask yourself:**
- Does this represent actual HTTP input, CLI input, or environment input?
- Would a developer actually call this to read user data?
- Is it a source for THIS specific vulnerability, or does it apply to all vulns?

**Every sanitizer you write must actually neutralize the specific vulnerability:**
- A SQLi sanitizer (parameterized query) does NOT protect against XSS.
- An XSS sanitizer (html.escape) does NOT protect against SQLi.
- A CMDi sanitizer (shlex.quote) does NOT protect against Path Traversal.
Write the correct sanitizer for the correct vuln class.

---

## THE REQUIRED YAML SCHEMA

Every rule file must have all of these fields. No exceptions. No empty values.

```yaml
rule_id: {language}_{vuln_short}_{number}
# Must be globally unique. No two files anywhere share a rule_id.
# Examples: python_sqli_001, go_cmdi_003, csharp_xxe_001, c_bof_005
# Use zero-padded 3-digit numbers: 001, 002, not 1, 2.

language: python|javascript|java|php|go|csharp|c|cpp
# Exactly one of these eight values.

vuln_class: {see allowed list below}
# Exactly one value from the allowed list. No variations. No "Best Practice".
# No trailing whitespace or newlines. "SQLi" not "Sqli" not "SQL Injection".

severity: Critical|High|Medium|Low
# Choose based on CVSS score:
# Critical = 9.0-10.0 | High = 7.0-8.9 | Medium = 4.0-6.9 | Low = 0.1-3.9

cwe: CWE-{number}
# The correct CWE number for this vulnerability.
# CWE-89=SQLi, CWE-78=CMDi, CWE-79=XSS, CWE-22=Path Traversal
# CWE-918=SSRF, CWE-611=XXE, CWE-502=Deserialization, CWE-94=Code Injection
# CWE-119=Buffer Overflow, CWE-134=Format String, CWE-416=Use After Free
# CWE-190=Integer Overflow, CWE-362=Race Condition
# Do NOT use CWE-1000. That is a research category, not a vulnerability.

owasp: A{number}:{year}-{name}
# The correct OWASP Top 10 2021 category. This field was missing from 942 rules.
# A01:2021-Broken Access Control
# A02:2021-Cryptographic Failures
# A03:2021-Injection
# A04:2021-Insecure Design
# A05:2021-Security Misconfiguration
# A06:2021-Vulnerable and Outdated Components
# A07:2021-Identification and Authentication Failures
# A08:2021-Software and Data Integrity Failures
# A09:2021-Security Logging and Monitoring Failures
# A10:2021-Server-Side Request Forgery

cvss_score: {float}
# The correct CVSS v3.1 base score.
# Network-exploitable injection (SQLi, CMDi, RCE): 9.8
# Stored XSS: 6.1 | Reflected XSS: 6.1
# SSRF: 8.6 | Path Traversal: 7.5 | XXE: 7.5
# Deserialization (leading to RCE): 9.8
# Buffer Overflow (arbitrary code execution): 8.8
# Format String: 8.8 | Integer Overflow: 7.5
# Weak Crypto: 5.9 | Hardcoded Secret: 7.5

cvss_vector: CVSS:3.1/{vector}
# Valid CVSS v3.1 vector string.
# Example for network-exploitable injection:
# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

confidence: Confirmed|Probable|Tentative
# Confirmed = taint analysis proves data flows from source to sink with no sanitizer
# Probable = strong structural pattern match, not full taint proof
# Tentative = heuristic detection, may need manual review
# C/C++ buffer overflow rules = Tentative (size analysis not possible statically)
# Pattern-based rules (weak crypto, hardcoded secrets) = Confirmed
# Taint rules with full source→sink chain = Confirmed

issue: "{one sentence, names the function and the vulnerability}"
# Good: "SQL Injection via cursor.execute() with string concatenation"
# Good: "Command Injection via subprocess.call() with shell=True"
# Bad:  "SQL Injection (CWE-89)"
# Bad:  "Potential vulnerability detected"
# Bad:  "Security issue found"

message: |
  {2-4 sentences. Must explain:
  1. What the vulnerability is and how it works mechanically
  2. What an attacker can do with it specifically
  3. Why the current code pattern is dangerous}
# This field was MISSING from 942 rules. It is now mandatory.
# Good example:
#   User-controlled data from request.args flows into cursor.execute() without
#   parameterization. An attacker can inject arbitrary SQL syntax to read sensitive
#   data from any table, modify or delete records, bypass authentication, or in
#   some database configurations execute OS commands via functions like xp_cmdshell.
# Bad example: "SQL injection vulnerability detected."
# Bad example: "This is a security vulnerability."

sources:
  # List of REAL functions or access patterns that introduce user-controlled data.
  # Rules for sources:
  # - Only include sources that are genuinely relevant to THIS vuln class
  # - Weak Crypto rules have NO sources (pattern-based) — write sources: []
  # - Hardcoded Secret rules have NO sources — write sources: []
  # - Do NOT include sanitizers in this list
  # - Do NOT include sinks in this list
  - real_source_function(

sinks:
  # List of REAL dangerous functions for THIS specific vulnerability.
  # Rules for sinks:
  # - Every sink must be a real function from this language
  # - Do NOT include sources in this list
  # - Do NOT include sanitizers in this list
  # - Be specific enough to not match safe usage
  # - One rule covers ONE sink or a small family of closely related sinks
  - real_sink_function(

sanitizers:
  # List of REAL functions that neutralize THIS SPECIFIC vulnerability.
  # Rules for sanitizers:
  # - Must be the correct sanitizer for this vuln class specifically
  # - SQLi sanitizer ≠ XSS sanitizer ≠ CMDi sanitizer
  # - If no sanitizer exists, write: []
  # - Do NOT write generic "validate input" — name the actual function
  - real_sanitizer_function(

remediation: |
  {3-5 sentences. Must include:
  1. What to STOP doing — name the specific vulnerable pattern
  2. What to DO INSTEAD — name the specific safe alternative
  3. A concrete code example showing the safe pattern in THIS language}
# This was "Validate and sanitize all user input." in 109 Go rules and 108 C# rules.
# That is useless. Write the actual fix with actual code.
# Good example:
#   Replace string concatenation in SQL queries with parameterized queries.
#   The database driver handles all escaping automatically.
#   UNSAFE: cursor.execute("SELECT * FROM users WHERE id='" + user_id + "'")
#   SAFE:   cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
#   Never pass user input directly into any SQL string.
```

---

## ALLOWED VULN_CLASS VALUES

Use exactly these strings. No variations. No trailing spaces.

```
SQLi              NoSQLi           CMDi
XSS               SSTI             SSRF
XXE               Path Traversal   Open Redirect
Deserialization   Code Injection   LDAP Injection
XPath Injection   Log Injection    Hardcoded Secret
Weak Crypto       JWT Bypass       Prototype Pollution
Buffer Overflow   Integer Overflow Format String
Use After Free    Memory Corruption Race Condition
Null Pointer Dereference          ReDoS
CSRF              Misconfiguration Cookie Security
```

`Best Practice` is NOT in this list. Delete every rule using it.

---

## WHAT TO DO — EXACT TASK ORDER

### TASK 1: DELETE ALL FABRICATED RULES

Delete every file matching these patterns without replacement:
```
rules/go/go_tier3_*.yaml          (approximately 100 files)
rules/csharp/csharp_tier3_*.yaml  (approximately 100 files)
```

These files contain fake sinks (`deprecated_function_10(`, `DeprecatedMethod10(`)
that do not exist in any real Go or C# codebase. They will never match real code.

After deletion, confirm what real rules remain per language and report the count.

---

### TASK 2: FIX EVERY STRUCTURAL ERROR

Go through every remaining YAML file and fix these specific problems:

**Fix A — Sources/Sinks/Sanitizers in Wrong Blocks**

For every rule file, verify:
- `sources:` block contains ONLY things that introduce user-controlled data
- `sinks:` block contains ONLY dangerous operations
- `sanitizers:` block contains ONLY functions that neutralize THIS vulnerability

Specific fixes required:
- Python `sqli_001.yaml`: Remove `'%s'`, `'?'`, `:param`, `execute` from `sources:` — those are sanitizers/sinks
- Python `ssrf.yaml`, `ssrf_009.yaml`, `ssrf_010.yaml`: Remove `urllib.request.urlopen` and `requests.get` from `sinks:` if they also appear in `sources:` — they are sinks, remove from sources
- PHP all SQLi rules: Remove `prepare(`, `bindParam(`, `bindValue(`, `real_escape_string` from `sinks:` — move them to `sanitizers:`
- JavaScript all CMDi rules: Verify `req.query` and `request.query` are in `sources:` not mixed with sinks

**Fix B — Add All Missing Required Fields**

For every rule file missing `owasp`, `message`, `cvss_score`, `cvss_vector`,
or `confidence`, add the correct values.

Do not copy-paste the same message across rules. Each message must describe
the specific sink in that rule.

**Fix C — Fix Duplicate vuln_class Values**

Audit shows these duplicates exist in the data:
- Python has both `vuln_class: Weak Crypto` and `vuln_class: Weak Crypto\n` (trailing newline)
- Python has both `vuln_class: Log Injection` and `vuln_class: Log Injection\n`
- Python has both `vuln_class: Hardcoded Secret` and `vuln_class: Hardcoded Secret\n`
- JavaScript has both `vuln_class: XSS` and `vuln_class: XSS\n`
- JavaScript has both `vuln_class: SQLi` and `vuln_class: SQLi\n`
- JavaScript has both `vuln_class: CMDi` and `vuln_class: CMDi\n`
- Java has both `vuln_class: Hardcoded Secret` and `vuln_class: Hardcoded Secret\n`

Strip all trailing whitespace and newlines from every vuln_class value.

**Fix D — Resolve Rule ID Collisions**

Every rule_id must be globally unique across all files in all language directories.
Run this check and fix every collision found:
```python
from pathlib import Path
import yaml
seen = {}
for f in Path("rules").rglob("*.yaml"):
    rule = yaml.safe_load(f.read_text())
    if rule and "rule_id" in rule:
        rid = rule["rule_id"]
        if rid in seen:
            print(f"COLLISION: {f} and {seen[rid]} both use '{rid}'")
        else:
            seen[rid] = f
```
Assign a new unique rule_id to any colliding file.

---

### TASK 3: FIX DUPLICATION WITHIN VULN CLASSES

The following vuln classes have too many files covering the same sinks.
Consolidate or differentiate them properly:

**Python SQLi (23 files, 38 unique sinks):**
Consolidate to one file per distinct framework or sink family:
- `python_sqli_raw_sql.yaml` — covers cursor.execute, connection.execute, db.execute
- `python_sqli_sqlalchemy.yaml` — covers SQLAlchemy raw(), text(), session.execute with raw SQL
- `python_sqli_django_orm.yaml` — covers Django .extra(), .raw(), .filter() with raw SQL
- `python_sqli_async.yaml` — covers asyncpg, aiosqlite, aiomysql
- `python_sqli_driver.yaml` — covers psycopg2.connect, pymysql.connect, cx_Oracle directly
Delete all other Python SQLi files after merging their unique sinks into the correct file.

**Python SSRF (27 files):**
Consolidate to one file per HTTP library:
- `python_ssrf_requests.yaml` — covers requests.get/post/put/delete/head/patch/request/Session
- `python_ssrf_urllib.yaml` — covers urllib.request.urlopen, urlretrieve, urllib2.urlopen
- `python_ssrf_httpx.yaml` — covers httpx.get, httpx.post, httpx.Client, httpx.AsyncClient
- `python_ssrf_aiohttp.yaml` — covers aiohttp.ClientSession, aiohttp.get, aiohttp.post
- `python_ssrf_other.yaml` — covers pycurl, httplib2, xmlrpc.client, grequests, urllib3

**JavaScript XSS (23 files):**
Consolidate to two files:
- `javascript_xss_dom.yaml` — covers innerHTML, outerHTML, document.write, insertAdjacentHTML, dangerouslySetInnerHTML
- `javascript_xss_eval.yaml` — covers eval(), new Function(), setTimeout with string, setInterval with string

**C and C++ Buffer Overflow:**
C and C++ are different languages with different safe alternatives.
Do NOT copy-paste C rules into C++. Write them separately:
- C rules: reference C standard library only (strncpy, strlcpy, fgets, snprintf)
- C++ rules: reference C++ alternatives (std::string, std::vector, std::copy_n, std::array)

---

### TASK 4: WRITE REAL RULES FOR GO AND C#

After deleting the tier3 placeholders, Go and C# have very few real rules.
Write complete, real rules for the following. Every sink listed here is a real
function from that language's standard library or most popular framework.

**Go — Required Rules:**

`go_sqli_database_sql.yaml`
```
vuln_class: SQLi
sinks: db.Query(, db.QueryRow(, db.Exec(, db.QueryContext(, db.QueryRowContext(, db.ExecContext(, tx.Query(, tx.QueryRow(, tx.Exec(
sanitizers: [] (parameterized via ? placeholder — detect by checking second arg is not string concat)
owasp: A03:2021-Injection
```

`go_sqli_gorm.yaml`
```
vuln_class: SQLi
sinks: db.Raw(, db.Where(, db.Exec(, db.First(  (only when called with raw string concat)
sanitizers: db.Prepare(
owasp: A03:2021-Injection
```

`go_cmdi_exec.yaml`
```
vuln_class: CMDi
sinks: exec.Command(, exec.CommandContext(
# Flag only when first arg contains user input OR when using exec.Command("sh", "-c", userInput)
sanitizers: [] (safe alternative: pass args as separate strings not via shell)
owasp: A03:2021-Injection
```

`go_xss_template.yaml`
```
vuln_class: XSS
sinks: template.HTML(, template.JS(, template.URL(, template.CSS(, fmt.Fprintf(w,
# text/template does NOT auto-escape — flag its usage
sanitizers: html/template (package import), template.HTMLEscapeString(, template.JSEscapeString(
owasp: A03:2021-Injection
```

`go_ssrf_http.yaml`
```
vuln_class: SSRF
sinks: http.Get(, http.Post(, http.Head(, http.NewRequest(, client.Get(, client.Do(, client.Post(
sanitizers: [] (use allowlist validation of URL host)
owasp: A10:2021-Server-Side Request Forgery
```

`go_path_traversal.yaml`
```
vuln_class: Path Traversal
sinks: os.Open(, os.Create(, os.ReadFile(, os.WriteFile(, ioutil.ReadFile(, ioutil.WriteFile(, http.ServeFile(, http.Dir(
sanitizers: filepath.Base(, filepath.Clean(
owasp: A01:2021-Broken Access Control
```

`go_weak_crypto.yaml`
```
vuln_class: Weak Crypto
sources: [] (pattern-based)
sinks: crypto.createHash("md5"  ← WRONG this is JS
# Go: md5.New(, sha1.New(, des.NewCipher(, rc4.NewCipher(, rand.Int(, rand.Float64(
sanitizers: sha256.New(, sha512.New(, crypto/rand (package), rand.Reader
owasp: A02:2021-Cryptographic Failures
```

`go_hardcoded_secret.yaml`
```
vuln_class: Hardcoded Secret
sources: [] (pattern-based, no taint)
sinks: [] (pattern-based, no taint)
# Detect: variable name matching secret pattern + string literal assignment
owasp: A07:2021-Identification and Authentication Failures
```

**C# — Required Rules:**

`csharp_sqli_sqlcommand.yaml`
```
vuln_class: SQLi
sinks: new SqlCommand(, SqlCommand(, .ExecuteReader(, .ExecuteNonQuery(, .ExecuteScalar(, .ExecuteReaderAsync(, .ExecuteNonQueryAsync(, new NpgsqlCommand(, MySqlCommand(
sanitizers: SqlParameter(, cmd.Parameters.Add(, cmd.Parameters.AddWithValue(
owasp: A03:2021-Injection
```

`csharp_sqli_ef.yaml`
```
vuln_class: SQLi
sinks: .ExecuteSqlRaw(, .ExecuteSqlRawAsync(, .FromSqlRaw(, DbContext.Database.ExecuteSqlRaw(
sanitizers: .ExecuteSqlInterpolated(, .FromSqlInterpolated(, FromSql(
owasp: A03:2021-Injection
```

`csharp_cmdi_process.yaml`
```
vuln_class: CMDi
sinks: Process.Start(, new ProcessStartInfo(, ProcessStartInfo(, System.Diagnostics.Process.Start(
sanitizers: [] (use allowlist validation, never pass user input as FileName)
owasp: A03:2021-Injection
```

`csharp_xss_response.yaml`
```
vuln_class: XSS
sinks: Response.Write(, Response.WriteAsync(, HttpContext.Response.WriteAsync(, @Html.Raw(, Html.Raw(, MvcHtmlString.Create(, HtmlHelper.Raw(
sanitizers: HttpUtility.HtmlEncode(, WebUtility.HtmlEncode(, HtmlEncoder.Default.Encode(
owasp: A03:2021-Injection
```

`csharp_path_traversal.yaml`
```
vuln_class: Path Traversal
sinks: File.ReadAllText(, File.WriteAllText(, File.Open(, File.Create(, File.ReadAllBytes(, new FileStream(, new StreamReader(, new StreamWriter(
sanitizers: Path.GetFileName(, Path.GetFullPath(
owasp: A01:2021-Broken Access Control
```

`csharp_deser_binaryformatter.yaml`
```
vuln_class: Deserialization
sinks: BinaryFormatter.Deserialize(, new BinaryFormatter(, LosFormatter.Deserialize(, ObjectStateFormatter.Deserialize(, NetDataContractSerializer.Deserialize(
sanitizers: [] (do not use BinaryFormatter — it is obsolete and has no safe mode)
owasp: A08:2021-Software and Data Integrity Failures
```

`csharp_deser_jsonnet.yaml`
```
vuln_class: Deserialization
sinks: JsonConvert.DeserializeObject(  (only when TypeNameHandling != None)
sanitizers: JsonConvert.DeserializeObject<KnownType>(, JsonSerializer.Deserialize<KnownType>(
owasp: A08:2021-Software and Data Integrity Failures
```

`csharp_xxe_xmldoc.yaml`
```
vuln_class: XXE
sinks: new XmlDocument(, new XmlTextReader(, XDocument.Load(, XElement.Load(, XmlReader.Create(
sanitizers: XmlReaderSettings DtdProcessing = DtdProcessing.Prohibit
owasp: A05:2021-Security Misconfiguration
```

`csharp_ssrf_httpclient.yaml`
```
vuln_class: SSRF
sinks: new HttpClient(, HttpClient.GetAsync(, HttpClient.PostAsync(, HttpClient.SendAsync(, WebClient.DownloadString(, WebRequest.Create(
sanitizers: [] (use allowlist validation of URL)
owasp: A10:2021-Server-Side Request Forgery
```

`csharp_weak_crypto.yaml`
```
vuln_class: Weak Crypto
sources: [] (pattern-based)
sinks: new MD5CryptoServiceProvider(, MD5.Create(, SHA1.Create(, new SHA1CryptoServiceProvider(, DES.Create(, RC2.Create(, new Random(
sanitizers: SHA256.Create(, SHA512.Create(, RandomNumberGenerator.Create(, RandomNumberGenerator.GetBytes(
owasp: A02:2021-Cryptographic Failures
```

---

### TASK 5: FIX C AND C++ RULES TO BE DISTINCT

C and C++ currently have identical rule files. They must be different.

**For C rules:**
- Sources: `gets(`, `fgets(`, `scanf(`, `fscanf(`, `sscanf(`, `read(`, `recv(`, `recvfrom(`, `getenv(`, `argv[`
- Buffer overflow sinks: `strcpy(`, `strcat(`, `sprintf(`, `vsprintf(`, `gets(`
- Buffer overflow sanitizers: `strncpy(`, `strncat(`, `snprintf(`, `fgets(`
- Format string sinks: `printf(`, `fprintf(`, `sprintf(`, `syslog(`, `err(`, `warn(`
- CMDi sinks: `system(`, `popen(`, `execl(`, `execlp(`, `execle(`, `execv(`, `execvp(`, `execve(`
- Confidence: `Tentative` for buffer overflow (size cannot be verified statically)

**For C++ rules — these are different from C:**
- Buffer overflow sinks: `strcpy(`, `strcat(`, `sprintf(` (same dangerous C functions used in C++)
- Buffer overflow sanitizers: `std::string` (instead of char*), `std::vector<char>`, `std::array`, `std::copy_n(`
- C++ does NOT need strncpy as a sanitizer — `std::string` is the correct alternative
- Format string: `printf(` family only — `std::cout <<` is NOT vulnerable to format string attacks
- C++ specific deserialization: `boost::archive::text_iarchive`, `boost::archive::binary_iarchive`, `cereal::JSONInputArchive`
- C++ specific SSRF: Does not apply at stdlib level — only via libcurl or Boost.Asio
- Confidence: `Tentative` for buffer overflow and integer overflow

---

### TASK 6: VALIDATE EVERY RULE BEFORE FINALIZING

Run this validation on every rule file you create or modify:

```python
import yaml
import os
from pathlib import Path

REQUIRED_FIELDS = [
    "rule_id", "language", "vuln_class", "severity", "cwe",
    "owasp", "cvss_score", "cvss_vector", "confidence",
    "issue", "message", "sources", "sinks", "sanitizers", "remediation"
]

ALLOWED_VULN_CLASSES = {
    "SQLi", "NoSQLi", "CMDi", "XSS", "SSTI", "SSRF", "XXE",
    "Path Traversal", "Open Redirect", "Deserialization", "Code Injection",
    "LDAP Injection", "XPath Injection", "Log Injection", "Hardcoded Secret",
    "Weak Crypto", "JWT Bypass", "Prototype Pollution", "Buffer Overflow",
    "Integer Overflow", "Format String", "Use After Free", "Memory Corruption",
    "Race Condition", "Null Pointer Dereference", "ReDoS", "CSRF",
    "Misconfiguration", "Cookie Security"
}

FORBIDDEN_SINKS = {
    "deprecated_function_", "DeprecatedMethod", "vulnerableSink",
    "fake_", "dummy_", "placeholder_", "_vuln", "vuln_func",
    "unsafe_func_", "test_sink_"
}

errors = []
seen_rule_ids = {}

for f in sorted(Path("rules").rglob("*.yaml")):
    try:
        rule = yaml.safe_load(f.read_text(encoding="utf-8"))
    except Exception as e:
        errors.append(f"PARSE ERROR {f}: {e}")
        continue

    if not rule:
        errors.append(f"EMPTY FILE: {f}")
        continue

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"MISSING FIELD '{field}': {f}")
        elif rule[field] is None or rule[field] == "":
            errors.append(f"EMPTY FIELD '{field}': {f}")

    # Check rule_id uniqueness
    rid = rule.get("rule_id", "")
    if rid in seen_rule_ids:
        errors.append(f"DUPLICATE rule_id '{rid}': {f} and {seen_rule_ids[rid]}")
    else:
        seen_rule_ids[rid] = f

    # Check vuln_class
    vc = str(rule.get("vuln_class", "")).strip()
    if vc not in ALLOWED_VULN_CLASSES:
        errors.append(f"INVALID vuln_class '{vc}': {f}")

    # Check for fabricated sinks
    sinks = rule.get("sinks", []) or []
    for sink in sinks:
        sink_str = str(sink)
        for forbidden in FORBIDDEN_SINKS:
            if forbidden.lower() in sink_str.lower():
                errors.append(f"FABRICATED SINK '{sink_str}': {f}")

    # Check message is substantial
    msg = str(rule.get("message", ""))
    if len(msg.strip()) < 50:
        errors.append(f"MESSAGE TOO SHORT (<50 chars): {f}")

    # Check remediation is substantial
    rem = str(rule.get("remediation", ""))
    if "validate and sanitize all user input" in rem.lower():
        errors.append(f"USELESS REMEDIATION (copy-paste boilerplate): {f}")
    if len(rem.strip()) < 80:
        errors.append(f"REMEDIATION TOO SHORT (<80 chars): {f}")

    # Check sanitizers are not in sources
    sources = rule.get("sources", []) or []
    sanitizer_patterns = ["escape(", "encode(", "sanitize(", "quote(", "prepare(", "bind"]
    for src in sources:
        for pat in sanitizer_patterns:
            if pat.lower() in str(src).lower():
                errors.append(f"SANITIZER IN SOURCES BLOCK '{src}': {f}")

print(f"Total files checked: {len(list(Path('rules').rglob('*.yaml')))}")
print(f"Total errors: {len(errors)}")
for e in errors:
    print(f"  ERROR: {e}")

if not errors:
    print("ALL RULES PASS VALIDATION")
else:
    print(f"\nFIX ALL {len(errors)} ERRORS BEFORE REPORTING COMPLETION")
    exit(1)
```

This script must output `ALL RULES PASS VALIDATION` with zero errors
before you report this task as complete.

---

## WHAT A CORRECT RULE LOOKS LIKE

This is the standard every rule must meet:

```yaml
rule_id: python_sqli_cursor_execute
language: python
vuln_class: SQLi
severity: Critical
cwe: CWE-89
owasp: A03:2021-Injection
cvss_score: 9.8
cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
confidence: Confirmed

issue: "SQL Injection via cursor.execute() with unsanitized user input"

message: |
  User-controlled data from an HTTP request parameter flows directly into
  cursor.execute() without parameterization. An attacker can inject arbitrary
  SQL syntax to read sensitive data from any table, modify or delete records,
  bypass authentication checks, or in some database configurations execute OS
  commands via xp_cmdshell (MSSQL) or INTO OUTFILE (MySQL).

sources:
  - request.args.get(
  - request.args[
  - request.form.get(
  - request.form[
  - request.json
  - request.get_json(
  - request.values.get(
  - request.data
  - request.cookies.get(
  - request.headers.get(
  - os.environ.get(
  - sys.argv[

sinks:
  - cursor.execute(
  - cursor.executemany(
  - connection.execute(
  - conn.execute(
  - db.execute(

sanitizers:
  - "%s"
  - "?"
  - ":param"
  - int(
  - float(

remediation: |
  Replace string concatenation or formatting in SQL queries with parameterized
  queries. The database driver handles all escaping automatically and the query
  structure cannot be altered by user input.

  UNSAFE:
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor.execute(query)

  SAFE (psycopg2 / MySQLdb):
    cursor.execute("SELECT * FROM users WHERE name=%s", (username,))

  SAFE (sqlite3):
    cursor.execute("SELECT * FROM users WHERE name=?", (username,))

  SAFE (SQLAlchemy with text()):
    session.execute(text("SELECT * FROM users WHERE name=:name"), {"name": username})

  Never build SQL strings from user input under any circumstances.
```

---

## WHAT YOU MUST NOT DO

Do not fabricate sinks. Every sink must be a real function from real documentation.
Do not use `vuln_class: Best Practice`. It is not in the allowed list.
Do not copy the same message across multiple rule files.
Do not write `remediation: Validate and sanitize all user input.` — that is forbidden.
Do not use CWE-1000 — that is a research category, not a specific vulnerability.
Do not leave `owasp:` empty or absent — it was missing from 942 rules and must now be in all.
Do not mark C/C++ buffer overflow rules as `confidence: Confirmed` — use `Tentative`.
Do not make C and C++ rules identical — they are different languages with different safe alternatives.
Do not create more files to inflate the count — consolidate duplicate coverage instead.
Do not put sanitizers in the sources block or sources in the sinks block — ever.

---

## REPORTING — WHAT YOU MUST SUBMIT

When done, submit all of the following. Do not submit partial results.

1. Rule count per language BEFORE and AFTER this task
2. Number of fabricated tier3 files deleted
3. Number of structural errors fixed (wrong block placement)
4. Number of missing fields added
5. Number of duplicate rule_ids resolved
6. For each language, name 3 sinks with their real package names — proving they are real:
   Example: `cursor.execute — Python DB-API 2.0 (PEP 249), package: sqlite3/psycopg2/MySQLdb`
7. Paste the complete output of the validation script showing zero errors
8. State the final rule count per language

Do not report completion without the validation script output.
