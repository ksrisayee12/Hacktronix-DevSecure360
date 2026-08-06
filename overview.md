# 🔐 DevSecure360 - Full Project Analysis & Overview

**DevSecure360** is a **Standalone Security Scanning SaaS Platform** designed to be a fully proprietary, end-to-end vulnerability scanning solution. It performs SAST, DAST, Port Scanning, Secret Detection, and Dependency Auditing with zero dependency on any external scanning tool or API.

## 1. Core Philosophy: "No Wrappers"
The fundamental rule of this project is that it is **not a wrapper**. While the initial prototype relied on external tools like Bandit, Semgrep, and OWASP ZAP (via subprocess and REST calls), the production product replaces these entirely with **native Python engines**.
*   **No Subprocesses:** No calling external binaries.
*   **No Third-Party Clouds:** All scanning logic and rule execution happens locally.
*   **Proof of Exploitability:** Findings are based on concrete data flows (Taint Traces) and dynamic exploitation (Oracles), not just regex pattern guesses.

## 2. Technology Stack & Architecture
*   **Backend:** Python 3.12, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy.
*   **Frontend:** React 18, React Router v6, Tailwind CSS, Recharts (for data visualization), Axios.
*   **Database & Queue:** PostgreSQL 15 (replacing flat JSON files) and Redis 7 for async job queues.
*   **SAST Core Libraries:** `tree-sitter` (for AST parsing of Python, JS, PHP, Java), `networkx` (for Control Flow Graphs), `pyyaml` (for rule loading).
*   **DAST Core Libraries:** `socket` and `ssl` (raw HTTP engine, explicitly avoiding `requests`), `beautifulsoup4` (HTML crawling), `playwright` (SPA crawling).

## 3. High-Level System Architecture & Shared Contract
The system operates asynchronously. The frontend submits jobs to FastAPI, which queues them in Redis. The scanners run and save results to PostgreSQL. 
A critical architectural constraint is the **Shared Contract** (`shared/types.py`). Every scanner strictly returns a `ScanResult` object containing standardized `Finding` objects. This allows the backend and frontend to seamlessly handle data regardless of which scanner produced it.

---

## 4. Feature Deep-Dive

### 4.1 Proprietary SAST Engine (Static Application Security Testing)
The SAST engine uses deep code analysis rather than regex, executing in 5 layers:
1.  **Parser (Tree-sitter):** Converts source code into a Concrete Syntax Tree (AST/CST).
2.  **CFG Builder:** Uses `networkx` to build a Control Flow Graph (basic blocks and execution paths).
3.  **Taint Engine (The Core):** Tracks user-controlled data (sources), propagates it through assignments/functions, and alerts if it reaches dangerous operations (sinks) without being neutralized (sanitizers). Tracks aliases and interprocedural calls.
4.  **YAML Rule Engine:** Uses custom declarative rules for vulnerability classes like SQLi, CMDi, Path Traversal, SSRF, SSTI, Deserialization, XSS, etc.
5.  **Reporter:** Formats findings and constructs a step-by-step **Taint Trace** proving exploitability.

### 4.2 Proprietary DAST Engine (Dynamic Application Security Testing)
The DAST engine attacks live URLs using 5 components:
1.  **Custom HTTP Engine:** Built entirely on raw sockets to maintain full control over payloads (allowing intentionally malformed packets).
2.  **Advanced Web Crawlers:** Combines an HTML Crawler (BeautifulSoup4) and an SPA Crawler (Playwright) to map endpoints and input fields.
3.  **Context-Aware Payload Engine:** Injects payloads customized for the exact context (e.g., HTML body, JS string, SQL query, URL path).
4.  **Detection Oracle:** Uses proof-of-exploitation logic (error-based, boolean-based, time-based diffs) to confirm vulnerabilities, ensuring near-zero false positives.
5.  **Out-of-Band (OOB) Listener:** Runs background DNS and HTTP servers to confirm "blind" vulnerabilities that do not reflect in the HTTP response.

### 4.3 High-Speed Port Scanner
*   Performs concurrent TCP Connect, half-open SYN, and UDP scans via `asyncio`.
*   Connects to open ports for banner grabbing and service fingerprinting.

### 4.4 Secret & Credential Scanner
*   **Regex Pattern Matching:** Detects specific cloud API keys (AWS, GitHub, Slack, etc.) and passwords.
*   **Shannon Entropy Detection:** Uses mathematical entropy calculations to identify high-entropy strings indicative of hidden secrets.
*   **Known File Patterns:** Flags sensitive files (`.env`, `.pem`, `id_rsa`).

### 4.5 Scoring & Dashboard
*   **CVSS-Based Scoring System:** Instead of simple weighted averages, DevSecure360 uses CVSS v3.1 base scoring, ensuring a single critical vulnerability correctly tanks the overall score.
*   **Unified Dashboard:** A React interface for real-time visualization of scan statistics, risk levels, severity charts, and historical trends.

---

## 5. Team Structure & MVP Timeline
The MVP is a 5-week target split across 3 parallel tracks:
*   **Platform Lead:** Owns the FastAPI backend, PostgreSQL, Redis job queue, CVSS scoring, UI components, and the Port/Secret scanners.
*   **SAST Engineer:** Owns the `tree-sitter` integration, CFG builder, Taint engine, YAML rules, and validation against ground-truth files (`vuln_flask.py`).
*   **DAST Engineer:** Owns the raw socket HTTP engine, crawlers, context-payload engine, detection oracles, and the OOB listener.

## 6. Strict Development Anti-Patterns
To ensure product integrity, the team strictly adheres to these rules:
1.  **Never use subprocess to run external tools:** Calling `bandit`, `semgrep`, or `ZAP` is forbidden.
2.  **Never use Regex for AST-level detection:** Syntax-aware tree-sitter parsing is mandatory.
3.  **Never import `requests` in the DAST HTTP engine:** Only raw sockets are allowed.
4.  **Never redefine the `Finding` or `ScanResult` classes:** Everything must adhere to the `shared/types.py` contract.
5.  **Never report a finding without evidence:** SAST requires a full `taint_trace`, and DAST requires HTTP response `evidence`.
6.  **Never hardcode localhost/127.0.0.1 in the frontend:** All URLs must load from `.env` configurations.
