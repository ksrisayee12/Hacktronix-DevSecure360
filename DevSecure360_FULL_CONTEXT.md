# DevSecure360 — Complete Project Context Document
> This document is the single source of truth for the DevSecure360 project.
> Any AI, developer, or new team member reading this document should have 100% context
> to contribute immediately without any prior knowledge of the project.

---

## 1. PROJECT IDENTITY

**Name:** DevSecure360  
**Type:** Standalone Security Scanning SaaS Platform  
**Purpose:** A fully proprietary, end-to-end security scanning platform that performs SAST, DAST, Port Scanning, Secret Detection, Dependency Auditing, and more — with zero dependency on any external scanning tool (no Bandit, no Semgrep, no ZAP, no external APIs).  
**Target Market:** Developers, security engineers, and organizations that need a self-contained, deployable security scanning product.  
**Stage:** MVP in active development. Existing prototype exists (DevSecure360-main). MVP target: 5 weeks.

---

## 2. ORIGIN AND WHAT ALREADY EXISTS

### 2.1 What Was Built First (The Prototype)
A working prototype exists at `DevSecure360-main/`. It has:
- A **React + Tailwind** frontend with pages: Dashboard, Code Scan, External Scan, History, About
- A **FastAPI** Python backend
- Integration with **Bandit** (Python SAST, via subprocess)
- Integration with **Semgrep** (multi-language SAST, via subprocess + their cloud rules)
- Integration with **OWASP ZAP** (DAST, via ZAP's REST API running as a Java process on port 8080)
- A flat JSON file (`scan_history.json`) as the database
- A basic scoring algorithm (weighted severity sum)

### 2.2 Why the Prototype Is Being Replaced
The prototype is a **wrapper** — it calls external tools and reformats their output. This is fundamentally broken for a commercial product because:
1. If Bandit/Semgrep/ZAP are not installed, the product fails completely
2. Semgrep pulls rules from their cloud — we don't own the scanning logic
3. ZAP runs as a separate Java process — not standalone
4. Bandit only covers Python — no multi-language support
5. No taint analysis — findings are pattern matches, not proven vulnerabilities
6. GPL/LGPL licensing risk on commercial SaaS
7. Cannot ship as a self-contained Docker container
8. Flat JSON database does not scale
9. No auth, no multi-tenancy

### 2.3 What Is Being Kept from the Prototype
- FastAPI backend structure and folder layout
- React frontend (pages, routing, Tailwind styling, Recharts dashboard)
- The `vuln codes/` folder (`vuln_flask.py`, `vuln_py.py`, `vuln_node.js`) — these become the ground-truth test suite
- The standardized finding format concept (file, issue, severity, tool)
- The score display logic on the frontend

### 2.4 What Is Being Completely Replaced
| Old | New |
|---|---|
| `backend/app/scanner/code_scanner.py` (calls Bandit + Semgrep) | `backend/app/scanner/sast/engine.py` (proprietary SAST engine) |
| `backend/app/scanner/external_scanner.py` (calls ZAP REST API) | `backend/app/scanner/dast/engine.py` (proprietary DAST engine) |
| `backend/app/database/history_db.py` (JSON flat file) | PostgreSQL with SQLAlchemy ORM |
| `backend/app/utils/aggregator.py` (simple weight formula) | CVSS-based scoring engine |
| `backend/requirements.txt` (includes semgrep, bandit) | New requirements with tree-sitter, networkx, etc. |

---

## 3. THE CORE PHILOSOPHY

> **"No wrappers. Everything is our engine."**

Every scan result produced by DevSecure360 must come from code we wrote. No subprocess calls to external security binaries. No REST calls to external scanner APIs. No pulling rules from third-party clouds.

The platform must:
- Run as a single Docker container
- Require zero external tool installation
- Own all scanning logic end-to-end
- Produce findings with proof of exploitability, not keyword guesses

---

## 4. FULL ARCHITECTURE

### 4.1 High-Level System Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                        React Frontend                           │
│   Dashboard | Code Scan | External Scan | Port | History        │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP (REST API)
┌────────────────────────────▼────────────────────────────────────┐
│                    FastAPI Backend (Python)                      │
│                   Scan Orchestrator + Job Queue                 │
├──────────┬──────────┬──────────┬──────────┬────────────────────┤
│   SAST   │   DAST   │  Port    │  Secret  │  Dep Auditor       │
│  Engine  │  Engine  │ Scanner  │ Scanner  │  (+ more modules)  │
├──────────┴──────────┴──────────┴──────────┴────────────────────┤
│              shared/types.py  (Finding, ScanResult, etc.)       │
├─────────────────────────────────────────────────────────────────┤
│              PostgreSQL (findings, history, users)              │
│              Redis (job queue)                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Backend Folder Structure
```
backend/
├── app/
│   ├── main.py                          ← FastAPI app, all endpoints
│   ├── shared/
│   │   └── types.py                     ← Shared dataclasses: Finding, ScanResult, Severity, etc.
│   ├── scanner/
│   │   ├── sast/
│   │   │   ├── engine.py                ← SAST entry point (replaces code_scanner.py)
│   │   │   ├── parser/
│   │   │   │   ├── base.py              ← tree-sitter initialization
│   │   │   │   ├── python_pack.py       ← Python AST traversal rules
│   │   │   │   ├── js_pack.py           ← JavaScript AST traversal
│   │   │   │   ├── php_pack.py          ← PHP AST traversal
│   │   │   │   └── java_pack.py         ← Java AST traversal
│   │   │   ├── cfg/
│   │   │   │   ├── builder.py           ← Control Flow Graph construction
│   │   │   │   └── graph.py             ← CFG data structures
│   │   │   ├── taint/
│   │   │   │   ├── engine.py            ← Core taint propagation
│   │   │   │   ├── aliases.py           ← Alias and collection tracking
│   │   │   │   └── interprocedural.py   ← Cross-function taint (call graph)
│   │   │   ├── rules/
│   │   │   │   ├── loader.py            ← YAML rule loader
│   │   │   │   ├── python/
│   │   │   │   │   ├── sqli.yaml
│   │   │   │   │   ├── cmdi.yaml
│   │   │   │   │   ├── xss.yaml
│   │   │   │   │   ├── path_traversal.yaml
│   │   │   │   │   ├── ssrf.yaml
│   │   │   │   │   ├── ssti.yaml
│   │   │   │   │   ├── deserialization.yaml
│   │   │   │   │   ├── hardcoded_secrets.yaml
│   │   │   │   │   └── weak_crypto.yaml
│   │   │   │   ├── javascript/
│   │   │   │   └── java/
│   │   │   └── reporter/
│   │   │       └── formatter.py         ← Finding standardization with taint trace
│   │   ├── dast/
│   │   │   ├── engine.py                ← DAST entry point (replaces external_scanner.py)
│   │   │   ├── http/
│   │   │   │   └── client.py            ← Raw HTTP engine (no requests/httpx wrappers)
│   │   │   ├── crawler/
│   │   │   │   ├── html_crawler.py      ← Static HTML link + form extraction
│   │   │   │   └── spa_crawler.py       ← JS-rendered page crawling
│   │   │   ├── payloads/
│   │   │   │   ├── sqli.py
│   │   │   │   ├── xss.py
│   │   │   │   ├── cmdi.py
│   │   │   │   ├── path_traversal.py
│   │   │   │   ├── ssrf.py
│   │   │   │   ├── xxe.py
│   │   │   │   ├── ssti.py
│   │   │   │   └── open_redirect.py
│   │   │   ├── detection/
│   │   │   │   ├── oracle.py            ← Proof-of-exploitation detection
│   │   │   │   └── differential.py      ← Response comparison analysis
│   │   │   └── oob/
│   │   │       └── listener.py          ← OOB DNS/HTTP callback server
│   │   ├── port/
│   │   │   └── scanner.py               ← TCP/UDP/SYN port scanner
│   │   └── secrets/
│   │       └── scanner.py               ← Hardcoded secret + entropy detection
│   ├── database/
│   │   ├── models.py                    ← SQLAlchemy models
│   │   └── session.py                   ← DB connection
│   ├── utils/
│   │   ├── aggregator.py                ← CVSS-based scoring (replaces old one)
│   │   └── queue.py                     ← Redis job queue
│   └── auth/
│       └── middleware.py                ← API key authentication
├── requirements.txt
└── .env
```

### 4.3 Frontend Structure (kept, expanded)
```
frontend/src/
├── App.js                   ← Router + Nav (kept)
├── config.js                ← API_BASE from env (FIX: was hardcoded localhost)
├── pages/
│   ├── Dashboard.js         ← Charts + history overview (kept, expand)
│   ├── CodeScan.js          ← SAST scan UI (kept, expand for taint trace)
│   ├── ExternalScan.js      ← DAST scan UI (kept)
│   ├── PortScan.js          ← NEW: port scan UI
│   ├── History.js           ← Scan history (kept)
│   └── About.js             ← About page (kept)
```

---

## 5. THE SHARED CONTRACT (shared/types.py)

This file is the single most important file in the project. Every engine reads from it. Nobody redefines these structures anywhere else.

```python
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"

class ScanType(str, Enum):
    SAST   = "sast"
    DAST   = "dast"
    PORT   = "port"
    SECRET = "secret"
    DEP    = "dependency"

class ScanStatus(str, Enum):
    QUEUED    = "queued"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"

@dataclass
class TaintStep:
    step: int
    line: int
    file: str
    description: str

@dataclass
class Finding:
    id: str                          # UUID
    rule_id: str                     # e.g. "python_sqli_001"
    vuln_class: str                  # "SQLi", "XSS", "CMDi", "SSRF", etc.
    scan_type: ScanType

    file: Optional[str]              # SAST: file path. DAST: None
    line: Optional[int]              # SAST: line number. DAST: None
    url: Optional[str]               # DAST: endpoint URL. SAST: None

    severity: Severity
    confidence: str                  # "Confirmed" / "Probable" / "Tentative"
    cwe: Optional[str]               # "CWE-89", "CWE-79", etc.
    owasp: Optional[str]             # "A03:2021", "A07:2021", etc.

    issue: str                       # Short human-readable title
    description: str                 # Full explanation of the vulnerability
    evidence: Optional[str]          # SAST: code snippet. DAST: HTTP request/response
    taint_trace: list[TaintStep]     # SAST only: source → propagation → sink
    remediation: str                 # Specific fix guidance

    tool: str                        # "devsecure_sast" / "devsecure_dast" / etc.

@dataclass
class ScanResult:
    scan_id: str
    scan_type: ScanType
    status: ScanStatus
    target: str                      # File path (SAST) or URL (DAST)
    findings: list[Finding]
    score: Optional[dict]
    started_at: str
    completed_at: Optional[str]
    error: Optional[str]
```

**Rule:** Every scan module returns `ScanResult`. The platform only deals with `ScanResult` objects. Nobody returns raw dicts.

---

## 6. SAST ENGINE — COMPLETE SPECIFICATION

### 6.1 What It Does
Takes a source code file or directory as input. Returns a `ScanResult` containing `Finding` objects, each with a full taint trace proving the vulnerability is exploitable.

### 6.2 The Five Layers (in order of execution)

#### Layer 1: Parser (tree-sitter)
- Uses the `tree-sitter` Python library
- Parses source code into a Concrete Syntax Tree (CST/AST)
- Does NOT use regex or string matching
- Each language has a "language pack" that knows:
  - How functions are defined in that language
  - How variables are assigned
  - How calls are structured
  - What the entry points look like
- Languages supported: Python, JavaScript, PHP, Java (MVP), then 36+ more via tree-sitter
- The parser outputs an AST node tree for each file

#### Layer 2: CFG Builder (Control Flow Graph)
- Takes the AST as input
- Builds a directed graph where:
  - Nodes = basic blocks (straight-line sequences of statements with no branches)
  - Edges = possible execution paths (if/else branches, loop back-edges, exception flows)
- Why it's needed: Without CFG, you miss that a variable can be tainted via one branch and reach a sink via another
- Uses `networkx` library for graph operations
- Output: A CFG per function

#### Layer 3: Taint Engine
- **The most critical component**
- Operates on CFG + AST
- Three core concepts:
  - **Sources**: Where user-controlled data enters (request params, form data, JSON body, env vars, CLI args)
  - **Sinks**: Where dangerous operations happen (SQL execution, subprocess calls, eval, file open, pickle.loads, template rendering)
  - **Sanitizers**: Functions that neutralize taint (int(), html.escape(), parameterized queries, etc.)
- Algorithm:
  1. Walk the CFG
  2. When a source is encountered, mark the variable as TAINTED
  3. Propagate taint through all subsequent assignments, operations, function calls
  4. If a TAINTED variable reaches a SINK without passing through a SANITIZER → VULNERABILITY CONFIRMED
- Alias tracking: `b = a` means `b` is also tainted. `c = {"key": b}` means `c["key"]` is tainted. `d = c["key"]` means `d` is tainted.
- Interprocedural: Taint crosses function boundaries via a call graph. If function A returns tainted data and function B calls A and passes the return value to a sink — that's a finding.

#### Layer 4: Rule Engine
- YAML-based rule definitions, one file per vulnerability class per language
- Each rule defines:
  - `sources`: list of function call patterns that introduce taint
  - `sinks`: list of function call patterns that are dangerous
  - `sanitizers`: list of patterns that neutralize taint
  - `message`: human-readable description
  - `cwe`: CWE identifier
  - `owasp`: OWASP Top 10 category
  - `severity`: High/Medium/Low
- Example rule (`python/sqli.yaml`):
  ```yaml
  rule_id: python_sqli_001
  language: python
  vuln_class: SQLi
  severity: High
  cwe: CWE-89
  owasp: A03:2021
  sources:
    - request.args.get
    - request.form.get
    - request.json
    - request.values.get
    - os.environ.get
    - sys.argv
  sinks:
    - db.execute
    - cursor.execute
    - connection.execute
    - engine.execute
    - session.execute
  sanitizers:
    - int()
    - float()
    - parameterized_pattern   # uses ? or %s placeholders
  message: "User input flows into SQL query without parameterization — SQL Injection"
  remediation: "Use parameterized queries: db.execute('SELECT * WHERE id=?', (user_id,))"
  ```

#### Layer 5: Reporter
- Takes confirmed findings from the taint engine
- Formats each into a `Finding` dataclass
- Builds the `taint_trace` list showing each step from source to sink
- Extracts the exact code snippet as evidence
- Maps to CWE and OWASP
- Returns a complete `ScanResult`

### 6.3 Vulnerability Classes Covered by SAST
| Class | How Detected | Example Sink |
|---|---|---|
| SQL Injection | Taint: HTTP param → db.execute | `cursor.execute("SELECT * WHERE name=" + name)` |
| NoSQL Injection | Taint: HTTP param → mongo.find | `db.users.find({"name": user_input})` |
| Command Injection | Taint: HTTP param → subprocess | `subprocess.call(cmd, shell=True)` |
| Code Injection / eval | Taint: HTTP param → eval() | `eval(user_expression)` |
| Path Traversal | Taint: HTTP param → open() | `open("/var/www/" + user_path)` |
| SSRF | Taint: HTTP param → requests.get | `requests.get(user_url)` |
| SSTI | Taint: HTTP param → render_template_string | `render_template_string(user_template)` |
| Deserialization | Taint: HTTP body → pickle.loads | `pickle.loads(request.data)` |
| Hardcoded Secrets | Pattern: variable name + string literal | `API_KEY = "sk-abc123"` |
| Weak Crypto | Pattern: md5/sha1/DES usage | `hashlib.md5(password)` |
| Open Redirect | Taint: HTTP param → redirect() | `redirect(request.args.get("next"))` |
| XSS (server-side) | Taint: HTTP param → render | `render_template_string("<b>" + user)` |

### 6.4 Ground Truth Test Files
These files exist in `vuln codes/` and the SAST engine MUST detect all of the following:

**vuln_flask.py:**
- Line ~12: `API_KEY = "super-secret-key-123"` → Hardcoded Secret
- Line ~26: `q = "SELECT id, name, email FROM users WHERE name = '%s'" % user` → SQL Injection
- Line ~35: `output = subprocess.check_output(cmd, shell=True, text=True)` → Command Injection

**vuln_py.py:**
- `subprocess.call("echo 'listing files' && dir", shell=True)` → Command Injection (shell=True)
- `return eval(expression)` → Code Injection
- `return pickle.loads(s)` → Deserialization
- `API_KEY = "hardcoded_api_key_12345"` → Hardcoded Secret

**Pass criteria:** All above vulns detected. Zero false positives on clean Python code.

### 6.5 Libraries Used by SAST Engine
```
tree-sitter          # AST parsing for 40+ languages
tree-sitter-python   # Python grammar
tree-sitter-javascript
tree-sitter-java
tree-sitter-php
networkx             # CFG and call graph (directed graphs)
pyyaml               # Rule file loading
uuid                 # Finding ID generation
```

---

## 7. DAST ENGINE — COMPLETE SPECIFICATION

### 7.1 What It Does
Takes a live URL as input. Crawls the application, injects payloads into every input point, analyzes responses to confirm vulnerability exploitation. Returns a `ScanResult` with findings backed by proof of exploitation.

### 7.2 The Five Components

#### Component 1: HTTP Engine (custom, no wrappers)
- Written using Python's `socket` and `ssl` modules only
- No `requests`, no `httpx`, no `urllib` wrappers
- Handles: HTTP/1.1, HTTPS, redirects (up to 10 hops), cookies, session persistence, custom headers
- Returns raw response: status code, headers, body
- Reason for raw implementation: control over every byte sent, ability to inject malformed payloads that libraries would reject

#### Component 2: Web Crawler
- **HTML Crawler**: Parses HTML with BeautifulSoup4, extracts:
  - All `<a href>` links
  - All `<form>` elements with their action URLs, method, and input fields
  - All `<script src>` references
  - All API endpoints visible in JS source
- **SPA Crawler**: Uses Playwright (headless Chrome via CDP) for JavaScript-rendered pages
  - Clicks through navigation
  - Intercepts XHR/fetch requests
  - Discovers routes not visible in static HTML
- Output: a map of all endpoints, input parameters, and their context (query param, POST body, header, cookie)

#### Component 3: Payload Engine
- For each discovered input point, determines the context:
  - Is this input reflected in HTML body → XSS payloads
  - Is this input used in a database query → SQLi payloads
  - Is this input used in a file path → Path traversal payloads
  - Is this input used in a URL → SSRF/Open Redirect payloads
- Context-aware payload selection (not blind spray):
  - HTML context: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`
  - Attribute context: `" onmouseover="alert(1)`
  - JS context: `';alert(1)//`
  - SQL context: `' OR '1'='1`, `' AND SLEEP(5)--`, `' UNION SELECT NULL--`
  - Command context: `; id`, `| whoami`, `$(id)`
  - Path context: `../../../etc/passwd`, `..%2F..%2Fetc%2Fpasswd`

#### Component 4: Detection Oracle
- **Not string matching** — proof of exploitation
- XSS: Uses headless browser to check if injected JS actually executed
- SQLi error-based: Checks for DB-specific error strings (`mysql_fetch`, `ORA-`, `PG::`)
- SQLi boolean-based: Sends two requests (true condition vs false condition), compares response length/content
- SQLi time-based: Sends `SLEEP(5)` payload, measures response time delta (>4.5s = confirmed)
- SQLi OOB: Payload triggers DNS lookup to OOB listener — callback confirms exploitation
- CMDi: Payload outputs unique token that appears in response
- Path traversal: Response contains `/etc/passwd` content (`root:x:0:0`)
- SSRF: Payload triggers HTTP request to OOB listener — callback confirms

#### Component 5: OOB Listener
- Runs as a background service on a controlled domain (e.g. `oob.devsecure360.io`)
- Two listeners:
  - **DNS listener**: Captures DNS lookups (for blind SSRF, blind SQLi OOB, blind XSS)
  - **HTTP listener**: Captures HTTP callbacks (for blind SSRF, XXE OOB)
- Correlation engine: Each payload contains a unique ID. When the OOB listener receives a callback with that ID, it correlates to the scan job and confirms the vulnerability.
- Without OOB, blind vulnerabilities (where no output is returned to the scanner) cannot be confirmed.

### 7.3 Vulnerability Classes Covered by DAST
| Class | Detection Method | Blind Version |
|---|---|---|
| SQL Injection | Error strings, boolean diff, time delay | OOB DNS callback |
| XSS (Reflected) | Headless browser JS execution check | N/A |
| XSS (Stored) | Second request checks if payload persists | N/A |
| Command Injection | Unique token in response | Time-based, OOB |
| Path Traversal | /etc/passwd content in response | N/A |
| SSRF | OOB HTTP callback | OOB DNS callback |
| XXE | Response content / OOB | OOB DNS/HTTP |
| Open Redirect | Response Location header check | N/A |
| CORS Misconfiguration | Origin header reflection check | N/A |
| Auth Bypass | JWT manipulation, session fixation | N/A |
| SSTI | Mathematical expression evaluation (`{{7*7}}` → 49) | N/A |

### 7.4 Libraries Used by DAST Engine
```
socket, ssl          # Raw HTTP engine (stdlib)
beautifulsoup4       # HTML parsing for crawler
playwright           # Headless browser for SPA crawling
asyncio              # Async HTTP requests for speed
```

---

## 8. PORT SCANNER — SPECIFICATION

### 8.1 What It Does
Takes an IP address or hostname + port range as input. Returns open ports, service names, and banner information.

### 8.2 Scan Types
- **TCP Connect Scan**: Full 3-way handshake (SYN → SYN-ACK → ACK). Reliable, no special privileges.
- **SYN Scan** (half-open): Sends SYN, receives SYN-ACK, sends RST instead of completing handshake. Faster, stealthier. Requires raw socket privileges.
- **UDP Scan**: Sends UDP packets, waits for ICMP port unreachable (closed) or response (open).

### 8.3 Features
- Concurrent scanning with asyncio (scan 1000 ports in seconds)
- Banner grabbing: connect to open port, read first 1024 bytes, identify service
- Service fingerprinting: match banner to known service signatures (HTTP, SSH, FTP, SMTP, etc.)
- Common port list: prioritize 1-1024, then well-known ports (3306, 5432, 6379, 27017, 8080, 8443, etc.)
- Output: list of `{port, state, service, banner, version_hint}`

### 8.4 Libraries Used
```
socket, asyncio      # Raw TCP/UDP (stdlib)
```

---

## 9. SECRET SCANNER — SPECIFICATION

### 9.1 What It Does
Takes a source code directory as input. Scans every file for hardcoded secrets, API keys, tokens, passwords, and credentials.

### 9.2 Detection Methods

**Method 1: Regex Pattern Matching**
Variable names matching secret patterns with string literal values:
```python
patterns = [
    r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']',
    r'(?i)(secret|passwd|password|token|auth)\s*=\s*["\'][^\s"\']{8,}["\']',
    r'(?i)(aws_access_key_id)\s*=\s*["\']AKIA[A-Z0-9]{16}["\']',
    r'sk-[A-Za-z0-9]{32,}',                  # OpenAI key pattern
    r'ghp_[A-Za-z0-9]{36}',                  # GitHub token pattern
    r'xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}',  # Slack bot token
]
```

**Method 2: Shannon Entropy Detection**
High-entropy strings are likely secrets even without obvious variable names.
```python
import math
def entropy(s):
    freq = {c: s.count(c)/len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())
# Strings >4.5 entropy and >20 chars in assignments are flagged
```

**Method 3: Known File Patterns**
Flag files that should never be committed: `.env`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`

### 9.3 False Positive Reduction
- Skip test files (paths containing `/test`, `/spec`, `/mock`)
- Skip example/template values (`YOUR_KEY_HERE`, `<API_KEY>`, `example`, `placeholder`)
- Skip empty strings and obvious dummy values

---

## 10. SCORING ENGINE — SPECIFICATION

### 10.1 Problem with Old Scoring
The old `aggregator.py` used: `score = 100 - (total_weight / max_possible) * 100`
This is meaningless. A single critical RCE should tank the score regardless of other findings.

### 10.2 New CVSS-Based Scoring
Each finding gets a CVSS v3.1 base score (0-10). The platform score is derived from the worst finding, not an average:

```python
CVSS_BASE = {
    "SQLi":         {"score": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "CMDi":         {"score": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "RCE":          {"score": 10.0},
    "XSS":          {"score": 6.1, "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "SSRF":         {"score": 8.6},
    "Path Traversal": {"score": 7.5},
    "SSTI":         {"score": 9.8},
    "Deserialization": {"score": 9.8},
    "Hardcoded Secret": {"score": 7.5},
    "Weak Crypto":  {"score": 5.9},
    "Open Redirect": {"score": 6.1},
    "CORS":         {"score": 5.4},
}

def compute_score(findings):
    if not findings:
        return {"score": 100, "grade": "A", "counts": {}}
    
    # Platform score = 100 - (highest CVSS score * 10)
    max_cvss = max(CVSS_BASE.get(f.vuln_class, {}).get("score", 5.0) for f in findings)
    platform_score = max(0, int(100 - (max_cvss * 10)))
    
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.severity.value] += 1
    
    grade = "A" if platform_score >= 90 else "B" if platform_score >= 75 else "C" if platform_score >= 60 else "D" if platform_score >= 40 else "F"
    
    return {"score": platform_score, "grade": grade, "counts": counts, "max_cvss": max_cvss}
```

---

## 11. DATABASE — SPECIFICATION

### 11.1 Move from JSON to PostgreSQL
Old: `scan_history.json` — single flat file, no concurrent access, no querying, data loss on crash
New: PostgreSQL with SQLAlchemy ORM

### 11.2 Schema
```python
# database/models.py
from sqlalchemy import Column, String, Integer, DateTime, JSON, Enum, Text
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(String, primary_key=True)       # UUID
    scan_type = Column(String)                   # sast/dast/port/secret
    status = Column(String)                      # queued/running/completed/failed
    target = Column(Text)                        # file path or URL
    created_at = Column(DateTime)
    completed_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    user_id = Column(String, nullable=True)      # for multi-tenancy

class ScanFinding(Base):
    __tablename__ = "scan_findings"
    id = Column(String, primary_key=True)
    scan_id = Column(String)                     # FK to scan_jobs.id
    rule_id = Column(String)
    vuln_class = Column(String)
    severity = Column(String)
    confidence = Column(String)
    file = Column(Text, nullable=True)
    line = Column(Integer, nullable=True)
    url = Column(Text, nullable=True)
    issue = Column(Text)
    description = Column(Text)
    evidence = Column(Text, nullable=True)
    taint_trace = Column(JSON)                   # list of TaintStep dicts
    remediation = Column(Text)
    cwe = Column(String, nullable=True)
    owasp = Column(String, nullable=True)
    tool = Column(String)
```

---

## 12. API ENDPOINTS — SPECIFICATION

### 12.1 Existing Endpoints (kept, updated internals)
```
GET  /                          → health check
POST /scan/code                 → SAST scan (file upload)
POST /scan/external             → DAST scan (URL input)
GET  /history                   → scan history
```

### 12.2 New Endpoints (to be added)
```
POST /scan/port                 → Port scan (host + port range)
POST /scan/secrets              → Secret scan (file/directory)
POST /scan/dependency           → Dependency CVE audit (requirements.txt / package.json)
GET  /scan/{scan_id}            → Get scan job status
GET  /scan/{scan_id}/findings   → Get findings for a specific scan
DELETE /scan/{scan_id}          → Delete scan result
GET  /findings/export/{scan_id} → Export findings as JSON/SARIF/PDF
POST /auth/apikey               → Generate API key (auth)
```

### 12.3 Request/Response Format
```python
# POST /scan/code
# Input: multipart/form-data with file
# Output:
{
  "scan_id": "uuid",
  "status": "completed",
  "findings": [
    {
      "id": "uuid",
      "rule_id": "python_sqli_001",
      "vuln_class": "SQLi",
      "scan_type": "sast",
      "file": "app/routes.py",
      "line": 42,
      "severity": "High",
      "confidence": "Confirmed",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "issue": "SQL Injection via unsanitized user input",
      "description": "...",
      "evidence": "q = \"SELECT * WHERE name='%s'\" % user",
      "taint_trace": [
        {"step": 1, "line": 38, "file": "app/routes.py", "description": "Source: request.args.get('name') → user is TAINTED"},
        {"step": 2, "line": 40, "file": "app/routes.py", "description": "Taint propagates via string formatting → q is TAINTED"},
        {"step": 3, "line": 42, "file": "app/routes.py", "description": "Sink: db.execute(q) called with TAINTED data → SQL INJECTION"}
      ],
      "remediation": "Use parameterized queries: db.execute('SELECT * WHERE name=%s', (user,))",
      "tool": "devsecure_sast"
    }
  ],
  "score": {"score": 12, "grade": "F", "counts": {"High": 1, "Medium": 0, "Low": 0}, "max_cvss": 9.8}
}
```

---

## 13. TEAM STRUCTURE AND RESPONSIBILITIES

### 13.1 Three-Person Split
The team is 3 people working in parallel on separate branches. They agree on the shared contract (`types.py`) on Day 1 and never block each other.

**Person 1 — Platform Lead (YOU)**
Owns: `backend/app/main.py`, `backend/app/database/`, `backend/app/utils/`, `backend/app/auth/`, `backend/app/scanner/port/`, `backend/app/scanner/secrets/`, `frontend/`

Responsibilities:
- PostgreSQL setup and migration from JSON flat file
- SQLAlchemy models
- FastAPI endpoint expansion (port scan, secret scan, status endpoints)
- Redis job queue setup
- Auth layer (API key middleware)
- Port scanner implementation
- Secret scanner implementation
- CVSS-based scoring engine
- Wire SAST and DAST engines into endpoints when Person 2 and Person 3 deliver
- Frontend expansion (port scan page, taint trace display, fix hardcoded localhost)
- End-to-end integration testing
- Docker setup

**Person 2 — SAST Engineer**
Owns: `backend/app/scanner/sast/`

Responsibilities:
- tree-sitter Python bindings setup
- Python language pack (AST traversal)
- CFG builder using networkx
- Intraprocedural taint engine
- Alias and collection tracking
- Rule engine + YAML rule loader
- SQLi, CMDi, eval, pickle, hardcoded secrets rules (Python)
- Reporter with taint trace formatting
- JavaScript and PHP language packs
- Interprocedural taint (call graph) — if time allows in MVP
- Daily validation: must detect all vulns in `vuln codes/` folder
- Accuracy benchmark vs Bandit output

**Person 3 — DAST Engineer**
Owns: `backend/app/scanner/dast/`

Responsibilities:
- Custom HTTP engine (raw sockets, no requests)
- HTML crawler (BeautifulSoup4)
- SPA crawler (Playwright)
- Payload engine for: SQLi, XSS, CMDi, Path Traversal, SSRF, Open Redirect
- Response oracle (proof-of-exploitation detection)
- Differential response analysis
- OOB listener (HTTP callback, DNS callback)
- Auth session handler (cookies, JWT)
- DAST findings formatted as `ScanResult`
- Accuracy benchmark vs ZAP output

### 13.2 Interface Contract Between Team Members
Person 1 calls Person 2's engine like this:
```python
from app.scanner.sast.engine import SASTEngine
engine = SASTEngine()
result: ScanResult = engine.scan(target_path="/path/to/code")
```

Person 1 calls Person 3's engine like this:
```python
from app.scanner.dast.engine import DASTEngine
engine = DASTEngine()
result: ScanResult = engine.scan(target_url="https://example.com")
```

Both return `ScanResult` from `shared/types.py`. Person 1 never cares about internals.

### 13.3 Git Branch Strategy
```
main                    ← protected, only merged PRs
feature/platform        ← Person 1
feature/sast-engine     ← Person 2
feature/dast-engine     ← Person 3
```

### 13.4 Daily Sync Rule
15-minute standup every day:
1. What did you build yesterday?
2. What are you building today?
3. What do you need from the other two?

---

## 14. WEEK-BY-WEEK MVP TIMELINE

### Week 1 — Foundation
**Person 1:** PostgreSQL setup, SQLAlchemy models, `shared/types.py`, new skeleton endpoints  
**Person 2:** tree-sitter setup, Python parser pack, raw AST printing of `vuln_flask.py`  
**Person 3:** Custom HTTP engine (GET/POST, redirects, cookies)

### Week 2 — Core Engines
**Person 1:** Port scanner (TCP connect scan, banner grab), Redis job queue skeleton  
**Person 2:** CFG builder, intraprocedural taint engine, first rule: SQLi → must detect `vuln_flask.py` line 26  
**Person 3:** HTML crawler (form discovery), first payload: SQLi error-based injection

### Week 3 — Rules + Detection
**Person 1:** Secret scanner, auth layer (API key), wire SAST engine into `/scan/code`  
**Person 2:** CMDi rule, hardcoded secrets rule, eval() rule, alias tracking. Validate all 7 vulns in test files.  
**Person 3:** XSS payload + headless browser check, CMDi payload + detection, path traversal

### Week 4 — Integration
**Person 1:** Wire DAST engine into `/scan/external`, CVSS scoring, frontend taint trace display, fix config  
**Person 2:** JavaScript language pack, PHP language pack, SSRF rule  
**Person 3:** OOB listener, auth session handler, SSTI payload

### Week 5 — Test + Deploy
**Everyone:** Cross-test, fix critical bugs, benchmark accuracy  
**Person 1:** Docker setup, environment config, E2E tests, deploy to server

---

## 15. TECHNOLOGY STACK

### Backend
```
Python 3.12
FastAPI                  # Web framework
Uvicorn                  # ASGI server
Pydantic v2              # Request/response validation
SQLAlchemy               # ORM
asyncpg / psycopg2       # PostgreSQL driver
Redis + rq               # Job queue
python-dotenv            # Environment config
```

### SAST Engine
```
tree-sitter              # Multi-language AST parser
tree-sitter-python       # Python grammar bindings
tree-sitter-javascript   # JavaScript grammar bindings
tree-sitter-java         # Java grammar bindings
tree-sitter-php          # PHP grammar bindings
networkx                 # CFG and call graph
pyyaml                   # Rule file loading
```

### DAST Engine
```
socket, ssl              # Raw HTTP engine (stdlib)
beautifulsoup4           # HTML parsing
playwright               # Headless browser (SPA crawling)
asyncio                  # Async operations
```

### Frontend
```
React 18
React Router v6
Tailwind CSS
Recharts                 # Dashboard charts
Axios                    # HTTP client
```

### Infrastructure
```
PostgreSQL 15            # Primary database
Redis 7                  # Job queue
Docker                   # Containerization
```

### Removed (no longer in requirements.txt)
```
bandit                   # REMOVED — replaced by SAST engine
semgrep                  # REMOVED — replaced by SAST engine
requests                 # REMOVED from DAST — replaced by raw socket engine
```

---

## 16. FULL PLATFORM MODULE MAP

### Phase 1 (MVP — 5 weeks)
- SAST Engine (Python, JS, PHP, Java)
- DAST Engine (SQLi, XSS, CMDi, Path Traversal, SSRF, Open Redirect, SSTI)
- Port Scanner (TCP connect scan, banner grabbing)
- Secret Scanner (regex + entropy)
- PostgreSQL migration
- Auth layer (API keys)
- CVSS scoring

### Phase 2 (Post-MVP)
- Dependency CVE Auditor (npm audit / pip audit equivalent, but our own CVE db lookup)
- IaC Scanner (Terraform, Docker, Kubernetes YAML misconfiguration)
- Container Scanner (Docker image layer analysis)
- SSL/TLS Analyzer (weak ciphers, expired certs, configuration issues)
- DNS Recon (record enumeration, zone transfer attempt, dangling DNS)
- Subdomain Enumerator (brute force + passive)
- WAF Detector (fingerprint and identify WAFs)
- Service Fingerprinter (exact version detection for running services)
- License Checker (GPL/AGPL violations in dependencies)
- CVE Correlator (match findings to NVD database)
- Remediation Engine (AI-assisted fix guidance)
- False Positive Scorer (confidence calibration)
- Trend Tracker (regression detection across scans)
- CI/CD integrations (GitHub Actions, GitLab CI, Jenkins)
- SARIF export (standard security finding format for IDEs)
- PDF report generation
- Multi-tenancy (complete data isolation between customers)

---

## 17. BUGS IN THE EXISTING PROTOTYPE

These must be fixed as part of the rebuild:

1. **Hardcoded localhost in frontend:**
   - `CodeScan.js`: `const API_BASE = "http://localhost:8000"` → must use `process.env.REACT_APP_API_BASE`
   - `History.js`: `fetch("http://127.0.0.1:8000/history")` → inconsistent address, must use config
   - `config.js` exists but is not being used by all pages

2. **Flat JSON database is not concurrent-safe:** Simultaneous scans will corrupt `scan_history.json`

3. **Score calculation is wrong:** A codebase with 100 Low findings scores 66%. A codebase with 1 Critical RCE and 99 Low findings scores similar. This must be replaced with CVSS-based scoring.

4. **No authentication:** Anyone with the backend URL can trigger scans, read all findings, and potentially scan arbitrary URLs/upload arbitrary code.

5. **`semgrep scan --config p/default` downloads rules at scan time** (network dependency, slow, non-deterministic).

6. **ZAP dependency:** If ZAP is not running on port 8080, the entire `/scan/external` endpoint returns 500.

7. **No job status:** Long scans block the HTTP response. Need async job queue so frontend can poll for status.

8. **No file type validation:** `/scan/code` accepts any file without validation.

---

## 18. KEY DESIGN DECISIONS AND REASONS

| Decision | What | Why |
|---|---|---|
| tree-sitter for parsing | Multi-language CST parser | Handles 40+ languages with one API, tolerates syntax errors, production-grade |
| networkx for CFG | Graph library | Industry standard for graph algorithms, handles cycles, strongly connected components |
| Raw sockets for DAST HTTP | No requests/httpx | Full control over every byte, can send malformed payloads libraries would reject |
| YAML rules | Declarative rule format | Security engineers can write rules without touching engine code |
| PostgreSQL over SQLite | Relational DB | Concurrent access, ACID compliance, scales to multi-tenant |
| Redis for job queue | Task queue | Simple, battle-tested, allows async scans without blocking HTTP |
| Python for everything | Single language | Existing backend is Python, best security library ecosystem, tree-sitter has great Python bindings |
| Proof-of-exploitation detection | Oracle-based | Eliminates false positives. Only confirmed vulns are reported. |
| OOB listener | DNS + HTTP callback server | Only way to detect blind vulnerabilities where no output is returned to scanner |
| Plugin architecture | Each module is independent | New scan types can be added without touching core. Engines are interchangeable. |

---

## 19. WHAT SUCCESS LOOKS LIKE FOR MVP

### SAST Success Criteria
- Detects all 7 known vulnerabilities in `vuln codes/` test files with zero false positives
- Produces taint traces showing source → propagation → sink for each finding
- Scans a 5,000-line Python codebase in under 30 seconds
- Outperforms Bandit on accuracy (fewer false positives, catches taint flows Bandit misses)

### DAST Success Criteria
- Detects SQL injection in a deliberately vulnerable test app (e.g. DVWA or a custom vuln Flask app)
- Detects XSS via headless browser confirmation
- Does not produce more than 10% false positives on a clean application
- Outperforms ZAP on blind vulnerability detection (OOB listener advantage)

### Platform Success Criteria
- Runs as a single `docker-compose up` with no external tool installation
- Handles 3 concurrent scans without data corruption
- Scan history stored in PostgreSQL, survives container restart
- Frontend shows taint traces in the findings table

---

## 20. WHAT NOT TO DO (ANTI-PATTERNS)

1. **Never call subprocess to run an external security tool.** If you're calling `subprocess.run(["bandit", ...])` or `subprocess.run(["semgrep", ...])` or hitting `http://localhost:8080/JSON/...` (ZAP API), you are building a wrapper, not an engine. This is explicitly forbidden.

2. **Never use regex for AST-level detection.** `re.search(r"eval\(", code)` is not SAST. It's a grep. Use tree-sitter AST traversal.

3. **Never import `requests` in the DAST HTTP engine.** Person 3 must use raw `socket` + `ssl` modules. The HTTP engine is our own code.

4. **Never redefine `Finding` or `ScanResult`.** These live in `shared/types.py`. If you need a new field, add it there and update every module. Never create a parallel dict structure.

5. **Never report a finding without evidence.** Every `Finding` must have either a `taint_trace` (SAST) or an `evidence` string showing the HTTP request/response that proved exploitation (DAST).

6. **Never hardcode localhost or 127.0.0.1 in frontend code.** All API URLs must come from `process.env.REACT_APP_API_BASE` loaded from `.env`.

7. **Never skip the ground truth test.** Person 2 must run `vuln_flask.py` and `vuln_py.py` through the SAST engine every single day. If any of the 7 known vulnerabilities stop being detected, something is broken and must be fixed before any new feature is added.

8. **Never use the JSON flat file for new code.** All persistence goes to PostgreSQL via SQLAlchemy. The JSON file is legacy and will be removed.

---

## 21. CONTEXT FOR NEW CHATS / NEW AI SESSIONS

If you are an AI assistant reading this document for the first time, here is everything you need to know to contribute:

- **The project is called DevSecure360** — a security scanning SaaS platform
- **Language:** Python (backend) + React (frontend)
- **Framework:** FastAPI backend, React 18 frontend
- **The core rule:** No external security tool binaries. Everything is built from scratch.
- **SAST:** Uses tree-sitter for AST parsing, networkx for CFG, custom taint engine
- **DAST:** Custom raw socket HTTP engine, BeautifulSoup4 crawler, custom payload + oracle system
- **Database:** PostgreSQL (migrated from JSON flat file)
- **Shared types:** `backend/app/shared/types.py` — never redefine `Finding`, `ScanResult`, `Severity`, `TaintStep`
- **Test files:** `vuln codes/vuln_flask.py` and `vuln codes/vuln_py.py` — the SAST engine must detect all vulnerabilities in these files
- **Team:** 3 people. Person 1 = Platform, Person 2 = SAST, Person 3 = DAST
- **MVP timeline:** 5 weeks
- **The engine interface:** Every scanner returns `ScanResult` from `shared/types.py`. The platform only calls `engine.scan(...)` and receives `ScanResult`.
- **When in doubt:** Check `shared/types.py` first. The contract is law.

---

*End of DevSecure360 Full Context Document*
*Version: 1.0 | Generated from full brainstorming and codebase analysis session*
