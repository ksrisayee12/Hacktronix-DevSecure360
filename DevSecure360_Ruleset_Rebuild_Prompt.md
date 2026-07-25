# DevSecure360 SAST Engine — Strict Ruleset Rebuild Prompt
# READ THIS ENTIRE DOCUMENT BEFORE WRITING A SINGLE YAML FILE.
# This is not a feature request. This is a quality enforcement directive.

---

## WHY THIS PROMPT EXISTS

The current ruleset was audited and found to be critically flawed:

- 942 out of 1,042 rule files are MISSING the `owasp` field
- 941 out of 1,042 rule files are MISSING the `message` field  
- Go has 109 files but 100 of them are fake "Best Practice" placeholders
- C# has 108 files but 100 of them are fake "Best Practice" placeholders
- Duplicate vuln_class names exist ("XSS" and "XSS\n", "SQLi" and "SQLi\n")
- Zero sanitizers defined in Go, C#, most C/C++ rules
- All remediation text in Go/C# is identical copy-paste: "Validate and sanitize all user input"
- No rule in ANY language has a properly written technical description

You fabricated rules to reach a number. That stops now.

---

## THE SINGLE MOST IMPORTANT RULE

**Every sink, source, and sanitizer you write must be a real function, method, or
API that exists in that language's standard library, ecosystem, or major frameworks.
You must be able to cite where it comes from.**

If you cannot name the package it belongs to, you cannot put it in a rule.
If you are not certain it is real, you do not include it.
A ruleset with 50 accurate rules is worth more than 1,000 fabricated ones.

---

## WHAT YOU MUST DO BEFORE WRITING ANY YAML

For each vulnerability class in each language, you must mentally answer:

1. What is the real function name in THIS language that creates the vulnerability?
2. What package or module does it come from?
3. What does the vulnerable code actually look like in a real application?
4. What is the correct fix a developer would apply?
5. What sanitizer or safe alternative exists in this language's ecosystem?

If you cannot answer all five questions, you do not write the rule.

---

## THE EXACT YAML SCHEMA — EVERY FIELD IS REQUIRED

Every single rule file must have ALL of the following fields.
A rule missing ANY field is considered incomplete and must be fixed.

```yaml
rule_id: {language}_{vuln_class_short}_{zero_padded_number}
# Examples: python_sqli_001, go_cmdi_003, csharp_xxe_001, c_bof_005
# Rule IDs must be globally unique across all files. No two files share an ID.

language: {python|javascript|java|php|go|csharp|c|cpp}

vuln_class: {exact class name — see allowed list below}
# Must match EXACTLY one of the allowed class names. No variations, no typos,
# no trailing whitespace. "SQLi" not "Sqli" not "SQL Injection" not "SQLi\n"

severity: {Critical|High|Medium|Low}
# Must be exactly one of these four values.

cwe: CWE-{number}
# Must be the correct CWE for this vulnerability.
# SQL Injection = CWE-89. Command Injection = CWE-78. XSS = CWE-79.
# Use the real CWE number. Do not use CWE-1000 (that is a category, not a vuln).

owasp: {OWASP category}
# Must be the correct OWASP Top 10 2021 category.
# Example: A03:2021-Injection, A02:2021-Cryptographic Failures
# Every rule must have this. No exceptions.

cvss_score: {float between 0.0 and 10.0}
# Must be the correct CVSS v3.1 base score for this specific vulnerability type.
# SQL Injection with network access = 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
# Stored XSS = 6.1. Reflected XSS = 6.1. Use the correct score.

cvss_vector: CVSS:3.1/{vector string}
# Must be a valid CVSS v3.1 vector string.

confidence: {Confirmed|Probable|Tentative}
# Confirmed = taint analysis proves it. Probable = strong pattern match.
# Tentative = heuristic. Be honest. Most taint rules = Confirmed.
# C/C++ memory rules without size analysis = Tentative, not Confirmed.

issue: {short human-readable title}
# One sentence. Specific. Names the function and the vulnerability.
# Good:  "SQL Injection via cursor.execute() with string concatenation"
# Bad:   "SQL Injection (CWE-89)"
# Bad:   "Potential vulnerability detected"

message: |
  {2-4 sentences explaining exactly what the vulnerability is, why it is dangerous,
  and what an attacker can do with it. Technical. Specific to this vuln class.}
# This is the field that was missing from 941 rules. It must not be empty.
# Good: "User-controlled data from request.args flows into cursor.execute() without
#        parameterization. An attacker can inject arbitrary SQL to read, modify,
#        or delete database records, or in some configurations execute OS commands."
# Bad:  "SQL injection vulnerability detected."
# Bad:  "" (empty)

sources:
  # List of REAL function calls, method accesses, or variable patterns
  # that introduce user-controlled data in this specific language.
  # Each source must be a real API from this language's ecosystem.
  # See the per-language source reference tables below.
  - real_function_name(
  - real.method.access

sinks:
  # List of REAL dangerous function calls or operations in this language.
  # EVERY sink must be a real function that exists in this language.
  # Must be specific enough to match the dangerous pattern without matching safe code.
  # Do NOT use generic terms like "deprecated_function_10(" or "DeprecatedMethod10("
  # Do NOT invent function names. Only real functions.
  - real_dangerous_function(

sanitizers:
  # List of REAL functions or patterns that neutralize this specific vulnerability.
  # If no sanitizer exists for this vuln class in this language, write: []
  # Do NOT leave this field out. Do NOT write fake sanitizers.
  # A sanitizer for SQLi is NOT a sanitizer for XSS. They are different.
  - real_sanitizer_function(

remediation: |
  {3-6 sentences of specific, actionable fix guidance. Must include:
  1. What to stop doing (the vulnerable pattern)
  2. What to do instead (the safe pattern)
  3. A concrete code example of the safe pattern in this language}
# Good:
#   "Replace string concatenation in SQL queries with parameterized queries.
#    Instead of: cursor.execute('SELECT * FROM users WHERE id=' + user_id)
#    Use: cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))
#    The database driver handles escaping. Never build SQL strings from user input."
# Bad: "Validate and sanitize all user input before passing to SQLi sinks."
# That bad example is what 100% of the Go and C# rules currently say. It is useless.
```

---

## ALLOWED VULN_CLASS VALUES — USE EXACTLY THESE STRINGS

Use only these exact strings for vuln_class. No variations.

```
SQLi
NoSQLi
CMDi
XSS
SSTI
SSRF
XXE
Path Traversal
Open Redirect
Deserialization
Code Injection
LDAP Injection
XPath Injection
Log Injection
Hardcoded Secret
Weak Crypto
JWT Bypass
Prototype Pollution
Buffer Overflow
Integer Overflow
Format String
Use After Free
Memory Corruption
Race Condition
Null Pointer Dereference
ReDoS
CSRF
Misconfiguration
Cookie Security
```

No "Best Practice". No "Injection". No "Potential vulnerability".
No trailing whitespace or newlines in the value.

---

## PER-LANGUAGE SOURCE AND SINK REFERENCE

These are the REAL sources and sinks you must use.
Every item listed here is a real function from that language's ecosystem.
You may add more only if you can verify they are real.

---

### PYTHON

**Real HTTP Sources (Flask):**
```
request.args.get(
request.args[
request.form.get(
request.form[
request.json
request.get_json(
request.data
request.values.get(
request.values[
request.cookies.get(
request.cookies[
request.headers.get(
request.headers[
request.files.get(
request.stream
```

**Real HTTP Sources (Django):**
```
request.GET.get(
request.GET[
request.POST.get(
request.POST[
request.body
request.META.get(
request.COOKIES.get(
request.FILES.get(
request.headers.get(
request.headers[
```

**Real HTTP Sources (FastAPI):**
```
# In FastAPI, the function parameter itself is the source when annotated with Query/Body
Query(
Body(
Form(
Path(
Header(
Cookie(
```

**Real System Sources:**
```
os.environ.get(
os.environ[
os.getenv(
sys.argv[
input(
```

**Real SQL Sinks (Python):**
```
cursor.execute(
cursor.executemany(
connection.execute(
conn.execute(
db.execute(
db.session.execute(
engine.execute(
engine.text(
session.execute(
.raw(
.filter(
```

**Real SQL Sanitizers (Python):**
```
# Parameterized query patterns — NOT function calls, but patterns
# %s placeholder (psycopg2)
# ? placeholder (sqlite3)
# :param placeholder (SQLAlchemy named)
# These are detected by checking if the first arg is a string with placeholders
# and user data is in the second tuple arg
int(
float(
```

**Real CMDi Sinks (Python):**
```
subprocess.call(
subprocess.run(
subprocess.Popen(
subprocess.check_output(
subprocess.check_call(
os.system(
os.popen(
os.execv(
os.execve(
os.spawnv(
commands.getoutput(
commands.getstatusoutput(
```

**Real CMDi Sanitizers (Python):**
```
shlex.quote(
pipes.quote(
shlex.split(
```

**Real XSS Sinks (Python):**
```
render_template_string(
Markup(
jinja2.Template(
.format(       # only when result passed to render
% operator     # only when result passed to render
```

**Real XSS Sanitizers (Python):**
```
html.escape(
markupsafe.escape(
bleach.clean(
bleach.linkify(
cgi.escape(
```

**Real Path Traversal Sinks (Python):**
```
open(
os.open(
os.path.join(
pathlib.Path(
io.open(
builtins.open(
zipfile.ZipFile(
tarfile.open(
shutil.copy(
shutil.move(
```

**Real Path Traversal Sanitizers (Python):**
```
os.path.basename(
os.path.abspath(
pathlib.Path.resolve(
```

**Real SSRF Sinks (Python):**
```
requests.get(
requests.post(
requests.put(
requests.delete(
requests.request(
requests.Session(
urllib.request.urlopen(
urllib.request.urlretrieve(
urllib.urlopen(
httplib.HTTPConnection(
http.client.HTTPConnection(
aiohttp.ClientSession(
httpx.get(
httpx.post(
httpx.Client(
```

**Real SSTI Sinks (Python):**
```
render_template_string(
jinja2.Template(
jinja2.Environment(
mako.template.Template(
Template(
string.Template(
```

**Real Deserialization Sinks (Python):**
```
pickle.loads(
pickle.load(
pickle.Unpickler(
yaml.load(
marshal.loads(
shelve.open(
jsonpickle.decode(
dill.loads(
```

**Real Deserialization Sanitizers (Python):**
```
yaml.safe_load(
json.loads(
ast.literal_eval(
```

**Real Weak Crypto Patterns (Python — pattern-based, no sources needed):**
```
hashlib.md5(
hashlib.sha1(
Crypto.Cipher.DES(
Crypto.Cipher.RC4(
Crypto.Cipher.Blowfish(
cryptography.hazmat.primitives.ciphers.algorithms.TripleDES(
random.random(
random.randint(
random.choice(
```

**Real Weak Crypto Sanitizers:**
```
hashlib.sha256(
hashlib.sha512(
hashlib.sha3_256(
secrets.token_bytes(
secrets.token_hex(
os.urandom(
```

---

### JAVASCRIPT / TYPESCRIPT (Node.js)

**Real HTTP Sources (Express.js):**
```
req.query.
req.query[
req.body.
req.body[
req.params.
req.params[
req.headers[
req.cookies.
req.cookies[
req.get(
```

**Real HTTP Sources (Fastify):**
```
request.query.
request.body.
request.params.
request.headers[
```

**Real System Sources:**
```
process.env.
process.argv[
readline.question(
```

**Real SQL Sinks (Node.js):**
```
connection.query(
pool.query(
db.query(
client.query(
sequelize.query(
knex.raw(
.query(
```

**Real NoSQL Sinks (MongoDB):**
```
collection.find(
collection.findOne(
collection.update(
collection.updateOne(
collection.deleteOne(
Model.find(
Model.findOne(
Model.findById(
Model.where(
```

**Real CMDi Sinks (Node.js):**
```
child_process.exec(
child_process.execSync(
child_process.spawn(
child_process.spawnSync(
child_process.execFile(
exec(
execSync(
spawn(
```

**Real CMDi Sanitizers:**
```
# No direct sanitizer — use execFile() with argument array instead of exec()
# or validate with allowlist
```

**Real XSS Sinks (Server-side rendering):**
```
res.send(
res.write(
res.end(
res.render(
innerHTML =
outerHTML =
document.write(
eval(
setTimeout(
setInterval(
new Function(
```

**Real XSS Sanitizers:**
```
DOMPurify.sanitize(
sanitizeHtml(
xss(
escapeHtml(
he.encode(
validator.escape(
```

**Real Path Traversal Sinks (Node.js):**
```
fs.readFile(
fs.readFileSync(
fs.writeFile(
fs.writeFileSync(
fs.createReadStream(
fs.createWriteStream(
fs.open(
path.join(
path.resolve(
require(
```

**Real Path Traversal Sanitizers:**
```
path.basename(
path.normalize(
```

**Real Prototype Pollution Sinks:**
```
Object.assign(
_.merge(
_.extend(
_.defaultsDeep(
jQuery.extend(
merge(
extend(
```

**Real Code Injection Sinks (Node.js):**
```
eval(
new Function(
vm.runInNewContext(
vm.runInThisContext(
vm.Script(
Function(
setTimeout(   # when first arg is string
setInterval(  # when first arg is string
```

**Real SSRF Sinks (Node.js):**
```
http.get(
http.request(
https.get(
https.request(
axios.get(
axios.post(
axios.request(
fetch(
node-fetch(
got(
request(
superagent.get(
```

**Real Weak Crypto (Node.js — pattern-based):**
```
crypto.createHash('md5'
crypto.createHash('sha1'
crypto.createCipher('des
crypto.createCipher('rc4
Math.random(
```

**Real Weak Crypto Sanitizers:**
```
crypto.createHash('sha256'
crypto.createHash('sha512'
crypto.randomBytes(
crypto.randomFillSync(
```

---

### JAVA

**Real HTTP Sources (Servlet/Spring):**
```
request.getParameter(
request.getParameterValues(
request.getHeader(
request.getHeaders(
request.getCookies(
request.getInputStream(
request.getReader(
request.getQueryString(
request.getPathInfo(
@RequestParam
@PathVariable
@RequestBody
@RequestHeader
@CookieValue
```

**Real SQL Sinks (Java):**
```
statement.execute(
statement.executeQuery(
statement.executeUpdate(
preparedStatement.execute(
connection.createStatement(
entityManager.createNativeQuery(
entityManager.createQuery(
session.createQuery(
session.createSQLQuery(
jdbcTemplate.execute(
jdbcTemplate.query(
jdbcTemplate.queryForObject(
jdbcTemplate.update(
```

**Real SQL Sanitizers (Java):**
```
prepareStatement(
PreparedStatement
setString(
setInt(
setLong(
@Query          # Spring Data JPA with named params
NamedParameterJdbcTemplate
```

**Real CMDi Sinks (Java):**
```
Runtime.exec(
Runtime.getRuntime().exec(
ProcessBuilder(
new ProcessBuilder(
new Process(
```

**Real XSS Sinks (Java):**
```
response.getWriter().write(
response.getWriter().print(
response.getWriter().println(
out.println(
PrintWriter.write(
model.addAttribute(   # when rendered without escaping
```

**Real XSS Sanitizers (Java):**
```
ESAPI.encoder().encodeForHTML(
StringEscapeUtils.escapeHtml4(
HtmlUtils.htmlEscape(
Encode.forHtml(
```

**Real XXE Sinks (Java):**
```
DocumentBuilderFactory.newInstance(
SAXParserFactory.newInstance(
XMLInputFactory.newInstance(
TransformerFactory.newInstance(
SchemaFactory.newInstance(
XMLReader
SAXParser
```

**Real XXE Sanitizers (Java):**
```
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
factory.setExpandEntityReferences(false)
```

**Real Deserialization Sinks (Java):**
```
ObjectInputStream(
readObject(
readUnshared(
XMLDecoder(
XStream.fromXML(
Yaml.load(
new ObjectMapper().readValue(   # only without type validation
```

**Real Path Traversal Sinks (Java):**
```
new File(
Paths.get(
FileInputStream(
FileOutputStream(
FileReader(
FileWriter(
Files.readAllBytes(
Files.write(
```

**Real JNDI/Log4Shell Sinks (Java):**
```
InitialContext.lookup(
context.lookup(
logger.info(    # when log4j 2.x and input contains ${
logger.error(
logger.debug(
logger.warn(
log.info(
log.error(
```

**Real Weak Crypto (Java — pattern-based):**
```
MessageDigest.getInstance("MD5"
MessageDigest.getInstance("SHA-1"
MessageDigest.getInstance("SHA1"
Cipher.getInstance("DES"
Cipher.getInstance("DESede"
Cipher.getInstance("RC4"
Cipher.getInstance("AES/ECB"
new Random(
Math.random(
```

**Real Weak Crypto Sanitizers (Java):**
```
MessageDigest.getInstance("SHA-256"
MessageDigest.getInstance("SHA-512"
MessageDigest.getInstance("SHA3-256"
Cipher.getInstance("AES/GCM"
SecureRandom(
```

---

### PHP

**Real HTTP Sources (PHP):**
```
$_GET[
$_GET['
$_POST[
$_POST['
$_REQUEST[
$_REQUEST['
$_COOKIE[
$_COOKIE['
$_SERVER[
$_SERVER['
$_FILES[
$_FILES['
getallheaders(
apache_request_headers(
file_get_contents('php://input')
filter_input(
```

**Real SQL Sinks (PHP):**
```
mysql_query(
mysqli_query(
mysqli::query(
$pdo->query(
$pdo->exec(
$db->query(
mssql_query(
pg_query(
pg_exec(
sqlite_query(
odbc_exec(
```

**Real SQL Sanitizers (PHP):**
```
prepare(
bindParam(
bindValue(
execute(        # only when used with prepare()
mysqli_real_escape_string(
mysql_real_escape_string(
pg_escape_string(
intval(
floatval(
(int)
(float)
filter_var(
```

**Real CMDi Sinks (PHP):**
```
system(
exec(
shell_exec(
passthru(
popen(
proc_open(
pcntl_exec(
`    ` (backtick operator)
preg_replace(   # when /e modifier used (PHP <7)
```

**Real CMDi Sanitizers (PHP):**
```
escapeshellarg(
escapeshellcmd(
```

**Real XSS Sinks (PHP):**
```
echo
print
printf
print_r(    # when output goes to browser
var_dump(   # when output goes to browser
header(     # when Location contains user input
```

**Real XSS Sanitizers (PHP):**
```
htmlspecialchars(
htmlentities(
strip_tags(
filter_var($x, FILTER_SANITIZE_SPECIAL_CHARS)
```

**Real Path Traversal Sinks (PHP):**
```
include(
include_once(
require(
require_once(
file_get_contents(
file_put_contents(
fopen(
readfile(
file(
copy(
move_uploaded_file(
unlink(
rmdir(
mkdir(
```

**Real PHP Object Injection Sinks:**
```
unserialize(
```

**Real PHP Object Injection Sanitizers:**
```
json_decode(    # use instead of unserialize
```

---

### GO

**Real HTTP Sources (net/http):**
```
r.URL.Query().Get(
r.URL.Query()[
r.FormValue(
r.PostFormValue(
r.Form.Get(
r.Header.Get(
r.Cookie(
r.Body
ioutil.ReadAll(r.Body
io.ReadAll(r.Body
```

**Real HTTP Sources (Gin framework):**
```
c.Query(
c.DefaultQuery(
c.Param(
c.PostForm(
c.DefaultPostForm(
c.GetHeader(
c.Cookie(
c.ShouldBindJSON(
c.BindJSON(
c.ShouldBind(
```

**Real HTTP Sources (Echo framework):**
```
c.QueryParam(
c.FormValue(
c.Param(
c.Request().Header.Get(
c.Cookie(
```

**Real System Sources (Go):**
```
os.Getenv(
os.Args[
flag.String(
flag.Parse(
```

**Real SQL Sinks (Go):**
```
db.Query(
db.QueryRow(
db.Exec(
db.QueryContext(
db.QueryRowContext(
db.ExecContext(
tx.Query(
tx.QueryRow(
tx.Exec(
```

**Real SQL Sanitizers (Go):**
```
# Go's database/sql uses ? placeholders — parameterized queries
# db.Query("SELECT * FROM users WHERE id=?", userID) is SAFE
# Detect safe pattern: string arg has ? and user data is in subsequent args
# sqlx named params: :param
```

**Real CMDi Sinks (Go):**
```
exec.Command(
exec.CommandContext(
os.StartProcess(
```

**Real CMDi Sanitizers (Go):**
```
# Pass arguments as separate strings to exec.Command, not via shell
# exec.Command("ls", userDir) is SAFE (no shell expansion)
# exec.Command("sh", "-c", userInput) is DANGEROUS
```

**Real XSS Sinks (Go):**
```
fmt.Fprintf(w,
w.Write(
io.WriteString(w,
template.HTML(
template.JS(
template.URL(
template.CSS(
```

**Real XSS Sanitizers (Go):**
```
html/template    # Go's html/template auto-escapes — use instead of text/template
template.HTMLEscapeString(
template.JSEscapeString(
```

**Real SSRF Sinks (Go):**
```
http.Get(
http.Post(
http.Head(
http.NewRequest(
http.DefaultClient.Do(
client.Get(
client.Do(
url.Parse(    # when result used in HTTP call
```

**Real Path Traversal Sinks (Go):**
```
os.Open(
os.Create(
os.ReadFile(
os.WriteFile(
ioutil.ReadFile(
ioutil.WriteFile(
filepath.Join(
http.ServeFile(
http.Dir(
```

**Real Path Traversal Sanitizers (Go):**
```
filepath.Base(
filepath.Clean(
strings.HasPrefix(
path.Clean(
```

---

### C# / .NET

**Real HTTP Sources (ASP.NET / ASP.NET Core):**
```
Request.QueryString[
Request.Form[
Request.Cookies[
Request.Headers[
Request.InputStream
Request.Url
Request.RawUrl
HttpContext.Request.Query[
HttpContext.Request.Form[
HttpContext.Request.Headers[
HttpContext.Request.Cookies[
HttpContext.Request.Body
[FromQuery]
[FromBody]
[FromForm]
[FromRoute]
[FromHeader]
Console.ReadLine(
Environment.GetCommandLineArgs(
Environment.GetEnvironmentVariable(
```

**Real SQL Sinks (C#):**
```
new SqlCommand(
SqlCommand(
.ExecuteReader(
.ExecuteNonQuery(
.ExecuteScalar(
.ExecuteReaderAsync(
.ExecuteNonQueryAsync(
new OleDbCommand(
new OdbcCommand(
new NpgsqlCommand(
MySqlCommand(
DbContext.Database.ExecuteSqlRaw(
DbContext.Database.ExecuteSqlRawAsync(
DbContext.Set<T>().FromSqlRaw(
```

**Real SQL Sanitizers (C#):**
```
SqlParameter(
new SqlParameter(
cmd.Parameters.Add(
cmd.Parameters.AddWithValue(
# Entity Framework parameterized: FromSqlInterpolated (safe)
# LINQ queries are safe by default
```

**Real CMDi Sinks (C#):**
```
Process.Start(
new ProcessStartInfo(
ProcessStartInfo(
Diagnostics.Process.Start(
```

**Real XSS Sinks (C#):**
```
Response.Write(
Response.WriteAsync(
HttpContext.Response.WriteAsync(
HtmlHelper.Raw(
@Html.Raw(
MvcHtmlString.Create(
```

**Real XSS Sanitizers (C#):**
```
HttpUtility.HtmlEncode(
WebUtility.HtmlEncode(
HtmlEncoder.Default.Encode(
AntiXssEncoder.HtmlEncode(
```

**Real Path Traversal Sinks (C#):**
```
File.ReadAllText(
File.WriteAllText(
File.Open(
File.Create(
File.ReadAllBytes(
File.WriteAllBytes(
new FileStream(
new StreamReader(
new StreamWriter(
Path.Combine(
Directory.GetFiles(
```

**Real Path Traversal Sanitizers (C#):**
```
Path.GetFileName(
Path.GetFullPath(
```

**Real Deserialization Sinks (C#):**
```
BinaryFormatter.Deserialize(
XmlSerializer.Deserialize(
DataContractSerializer.ReadObject(
NetDataContractSerializer.Deserialize(
LosFormatter.Deserialize(
ObjectStateFormatter.Deserialize(
JsonConvert.DeserializeObject(   # only without type validation
```

**Real Deserialization Sanitizers (C#):**
```
JsonConvert.DeserializeObject<KnownType>(   # safe with explicit known type
JsonSerializer.Deserialize<KnownType>(
```

**Real XXE Sinks (C#):**
```
new XmlDocument(
new XmlTextReader(
XDocument.Load(
XElement.Load(
XmlReader.Create(
```

**Real XXE Sanitizers (C#):**
```
XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }
XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore }
```

**Real Weak Crypto (C# — pattern-based):**
```
new MD5CryptoServiceProvider(
MD5.Create(
SHA1.Create(
new SHA1CryptoServiceProvider(
DES.Create(
RC2.Create(
new RijndaelManaged(   # ECB mode
RNGCryptoServiceProvider   # deprecated in .NET 6+
new Random(
```

**Real Weak Crypto Sanitizers (C#):**
```
SHA256.Create(
SHA512.Create(
Aes.Create(    # with GCM mode
RandomNumberGenerator.Create(
RandomNumberGenerator.GetBytes(
```

---

### C

**Important note on C analysis:** C does not have HTTP frameworks. Sources in C
are typically stdin, command-line arguments, environment variables, and network
sockets. Sinks are unsafe C standard library functions. Confidence for C rules
should be `Tentative` because size information needed to confirm overflow is
not available from text-based analysis alone.

**Real Sources (C):**
```
gets(           # always unsafe regardless of input
fgets(
scanf(
fscanf(
sscanf(
read(
recv(
recvfrom(
getenv(
argv[
getchar(
fread(
pread(
```

**Real Buffer Overflow Sinks (C):**
```
strcpy(
strcat(
sprintf(
vsprintf(
gets(           # always a sink AND a source simultaneously — always flag
memcpy(         # only when size arg is derived from untrusted source
memmove(        # same as memcpy
bcopy(
```

**Real Buffer Overflow Sanitizers (C — safer alternatives):**
```
strncpy(    # still requires care with size
strncat(    # still requires care with size
snprintf(   # correct replacement for sprintf
strlcpy(    # OpenBSD/macOS
strlcat(    # OpenBSD/macOS
fgets(      # replacement for gets()
```

**Real Format String Sinks (C):**
```
printf(
fprintf(
sprintf(
snprintf(
vprintf(
vfprintf(
vsprintf(
vsnprintf(
syslog(
err(
warn(
```

**Real CMDi Sinks (C):**
```
system(
popen(
execl(
execlp(
execle(
execv(
execvp(
execve(
execvpe(
```

**Real CMDi Sanitizers (C):**
```
# No direct sanitizer — use execv-family with argument array, not system()
# Validate input against strict allowlist
```

**Real Integer Overflow Patterns (C):**
```
malloc(      # when size arg is arithmetic on user input
calloc(      # same
realloc(     # same
memcpy(      # when size arg is arithmetic on user input
# Detect: malloc(user_val * sizeof(type)) without overflow check
```

**Real Use-After-Free Patterns (C — CFG required):**
```
free(        # mark pointer as freed
# Then detect: freed pointer used in subsequent dereference
# This requires CFG analysis to detect properly
```

---

### C++

All C sinks apply to C++ plus the following:

**Real C++ Specific Sinks:**
```
new[]           # when size from user input (array new)
std::string(    # when length from user input
std::vector::resize(  # when size from user input
system(
std::system(
popen(
```

**Real Deserialization Sinks (C++):**
```
boost::archive::text_iarchive
boost::archive::binary_iarchive
cereal::JSONInputArchive
```

**Real Format String Sinks (C++):**
```
printf(
sprintf(
fprintf(
# Note: std::cout << does NOT have format string vulnerabilities
# std::string::format() in C++20 is NOT vulnerable
```

---

## WHAT YOU MUST DO — THE EXACT TASK

### Step 1: Audit Every Existing Rule File

Go through every YAML file in every language directory. For each file:

1. Check if the rule_id is globally unique. If not, assign a new unique ID.
2. Check if all required fields are present. If not, add them.
3. Check if every sink is a real function from that language. If not, replace or remove it.
4. Check if the message field is a real technical description (2-4 sentences, specific).
5. Check if the remediation is specific (includes what to stop doing AND a code example).
6. Check that owasp is the correct OWASP Top 10 2021 category.
7. Check that cvss_score is numerically correct for this vulnerability type.

### Step 2: Delete All Fabricated Rules

Delete without replacement:
- All files in `rules/go/` matching `go_tier3_*.yaml`
- All files in `rules/csharp/` matching `csharp_tier3_*.yaml`
- Any file where every sink is a function you cannot find in real documentation

### Step 3: For Each Language, Write the Missing Real Rules

After audit and cleanup, identify which vuln classes have zero or weak coverage
and write new rules using ONLY the sources and sinks from the reference tables above.

**Minimum required coverage per language (these must exist and be complete):**

| Language | Required Vuln Classes |
|---|---|
| Python | SQLi, CMDi, XSS, SSRF, SSTI, Path Traversal, Open Redirect, Deserialization, XXE, Code Injection, Weak Crypto, Hardcoded Secret, Log Injection, NoSQLi, LDAP Injection |
| JavaScript | SQLi, NoSQLi, CMDi, XSS, Path Traversal, SSRF, Prototype Pollution, Code Injection, Open Redirect, Weak Crypto, Cookie Security, JWT Bypass |
| Java | SQLi, CMDi, XSS, XXE, Path Traversal, SSRF, Deserialization, LDAP Injection, XPath Injection, Weak Crypto, Log Injection (Log4Shell) |
| PHP | SQLi, CMDi, XSS, Path Traversal, SSRF, XXE, Deserialization, Code Injection, Open Redirect |
| Go | SQLi, CMDi, XSS, Path Traversal, SSRF, Weak Crypto, Hardcoded Secret |
| C# | SQLi, CMDi, XSS, Path Traversal, SSRF, XXE, Deserialization, Weak Crypto, Open Redirect |
| C | Buffer Overflow, Format String, CMDi, Integer Overflow, Use After Free, Race Condition |
| C++ | Buffer Overflow, Format String, CMDi, Integer Overflow, Use After Free, Deserialization |

### Step 4: Validate Every Rule You Write or Modify

Before finalizing any rule, verify:

- [ ] The sink function actually exists in this language (you can name its package)
- [ ] The source function actually exists in this language
- [ ] The sanitizer actually neutralizes THIS specific vulnerability (not a generic validator)
- [ ] The rule_id is unique across ALL files in ALL languages
- [ ] All 11 required fields are present and non-empty
- [ ] The message is 2-4 sentences, technical, specific to this vuln class
- [ ] The remediation includes a concrete code example

---

## WHAT YOU MUST NOT DO

**DO NOT** write a sink like `deprecated_function_10(` — that is not real.
**DO NOT** write a sink like `vulnerableSink(` — that is not real.
**DO NOT** write `remediation: Validate and sanitize all user input.` — that is useless.
**DO NOT** write `message: SQL injection vulnerability detected.` — that is useless.
**DO NOT** set `vuln_class: Best Practice` — that is not a vulnerability class.
**DO NOT** copy the same source list to every rule in a language without thinking
  about whether those sources actually lead to that specific vulnerability.
**DO NOT** create more than one rule file per (language + vuln_class + sink_function).
  If SQLi via cursor.execute is already covered, do not create a second file for it.
**DO NOT** use CWE-1000 — that is a research concept category, not a real CWE.
**DO NOT** claim Confirmed confidence for C/C++ buffer overflow rules — size
  analysis is not possible without runtime information. Use Tentative.
**DO NOT** inflate the rule count. 200 complete, accurate rules is better than
  1,000 incomplete fabricated ones. Quality over quantity, always.

---

## REPORTING BACK

When complete, report:

1. Total rules per language BEFORE and AFTER cleanup
2. How many rules were deleted (fabricated tier3 rules)
3. How many rules were fixed (missing fields added)
4. How many new rules were written
5. Confirm that every sink in every rule is a real function by listing
   3 examples per language with the package name they come from
6. Run the validation script and paste the complete output

---

## EXAMPLE OF A COMPLETE, CORRECT RULE

This is what every rule in the engine must look like after this task is complete:

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
  or in some database configurations execute operating system commands via
  functions like xp_cmdshell (MSSQL) or INTO OUTFILE (MySQL).

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
  Replace string concatenation or string formatting in SQL queries with
  parameterized queries. The database driver handles all escaping automatically.

  UNSAFE:
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor.execute(query)

  SAFE (psycopg2/MySQLdb):
    cursor.execute("SELECT * FROM users WHERE name=%s", (username,))

  SAFE (sqlite3):
    cursor.execute("SELECT * FROM users WHERE name=?", (username,))

  SAFE (SQLAlchemy):
    session.execute(text("SELECT * FROM users WHERE name=:name"), {"name": username})

  Never build SQL strings by concatenating or formatting user input.
  If using an ORM, use its parameterized query interface instead of raw().
```

That is the standard. Every rule must meet it.
