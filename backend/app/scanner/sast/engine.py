# backend/app/scanner/sast/engine.py
"""
DevSecure360 Proprietary SAST Engine — Public Entry Point

This is the file that main.py imports. It orchestrates the full pipeline:
    1. File collection (by supported extension)
    2. Language-appropriate AST parsing (tree-sitter)
    3. Structured info extraction (assignments, calls, functions)
    4. Taint analysis (source → propagation → sink)
    5. Pattern-based secret detection
    6. Finding assembly and ScanResult return

Supported languages (Phase 1):
    Python (.py), JavaScript (.js, .ts, .jsx, .tsx),
    Java (.java), PHP (.php), C (.c, .h), C++ (.cpp, .cc, .cxx, .hpp)

Usage:
    engine = SASTEngine()
    result: ScanResult = engine.scan(target_path="/path/to/code")
"""

import os
import uuid
from datetime import datetime

from app.shared.types import ScanResult, ScanStatus, ScanType, Finding, Severity

from .parser.base import parse_file, is_language_supported, supported_extensions
from .parser.python_pack import extract_python_info
from .parser.js_pack import extract_js_info
from .parser.java_pack import extract_java_info
from .parser.php_pack import extract_php_info
from .parser.c_pack import extract_c_info
from .cfg.builder import build_cfg
from .taint.engine import TaintEngine
from .rules.loader import load_rules, load_all_rules
from .taint.secrets import AdvancedSecretScanner, SecretFinding
from .taint.redos import AdvancedReDoSScanner, ReDoSFinding
from .reporter.formatter import taint_finding_to_finding, secret_finding
from .config_scanner import ConfigScanner

# Directories to skip when scanning
SKIP_DIRS = {
    'node_modules', '__pycache__', '.git', 'venv', '.venv',
    'dist', 'build', '.idea', '.vscode', 'target', 'bin', 'obj',
    'coverage', '.nyc_output', 'vendor', 'bower_components'
}


class SASTEngine:
    """
    DevSecure360 Proprietary SAST Engine.

    Detects:
        Python:     SQLi, CMDi, eval/exec injection, insecure deserialization, hardcoded secrets
        JavaScript: SQLi, XSS, CMDi, hardcoded secrets
        Java:       SQLi, CMDi, hardcoded secrets
        PHP:        SQLi, CMDi, XSS
        C/C++:      Buffer overflow, CMDi

    NEVER calls external tools (bandit, semgrep, etc.)
    ALWAYS returns ScanResult — never raises, errors go into result.error
    """

    def __init__(self):
        # Load rules for all supported languages once at initialization
        self.rules: dict[str, dict] = {
            "python":     load_rules("python"),
            "javascript": load_rules("javascript"),
            "java":       load_rules("java"),
            "php":        load_rules("php"),
            "c":          load_rules("c"),
            "cpp":        load_rules("cpp"),
        }
        print(f"[SASTEngine] Rules loaded: "
              + ", ".join(f"{lang}={len(r)}" for lang, r in self.rules.items()))

    def scan(self, target_path: str) -> ScanResult:
        """
        Scan a file or directory for security vulnerabilities.

        Args:
            target_path: Absolute path to a file or directory to scan.

        Returns:
            ScanResult with all findings. Never raises — errors go into result.error.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.utcnow().isoformat()
        all_findings: list[Finding] = []

        try:
            files = self._collect_files(target_path)
            print(f"[SASTEngine] Scanning {len(files)} file(s) in: {target_path}")

            for file_path in files:
                ext = os.path.splitext(file_path)[1].lower()
                try:
                    findings = self._scan_file(file_path, ext)
                    all_findings.extend(findings)
                    if findings:
                        print(f"[SASTEngine] {file_path}: {len(findings)} finding(s)")
                except Exception as e:
                    print(f"[SASTEngine] Warning: failed to scan {file_path}: {e}")
                    continue

            return ScanResult(
                scan_id=scan_id,
                scan_type=ScanType.SAST,
                status=ScanStatus.COMPLETED,
                target=target_path,
                findings=all_findings,
                score=None,  # computed by aggregator in main.py
                started_at=started_at,
                completed_at=datetime.utcnow().isoformat(),
                error=None
            )

        except Exception as e:
            return ScanResult(
                scan_id=scan_id,
                scan_type=ScanType.SAST,
                status=ScanStatus.FAILED,
                target=target_path,
                findings=[],
                score=None,
                started_at=started_at,
                completed_at=datetime.utcnow().isoformat(),
                error=str(e)
            )

    def _collect_files(self, target_path: str) -> list[str]:
        """Collect all supported code and config files from a path."""
        files = []
        config_files = {".env", "docker-compose.yml", "docker-compose.yaml", "package.json"}
        
        if os.path.isfile(target_path):
            ext = os.path.splitext(target_path)[1].lower()
            basename = os.path.basename(target_path).lower()
            if is_language_supported(ext) or basename in config_files:
                files.append(target_path)
        elif os.path.isdir(target_path):
            for root, dirs, filenames in os.walk(target_path):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in SKIP_DIRS]
                for filename in filenames:
                    ext = os.path.splitext(filename)[1].lower()
                    basename = filename.lower()
                    if is_language_supported(ext) or basename in config_files:
                        files.append(os.path.join(root, filename))
        return files

    def _scan_file(self, file_path: str, extension: str) -> list[Finding]:
        """Dispatch file to the appropriate language scanner or config scanner."""
        basename = os.path.basename(file_path).lower()
        config_files = {".env", "docker-compose.yml", "docker-compose.yaml", "package.json"}
        if basename in config_files:
            return ConfigScanner.scan_file(file_path)

        with open(file_path, "rb") as f:
            source_bytes = f.read()

        source_code = source_bytes.decode("utf-8", errors="replace")

        # Parse the file into a tree-sitter AST
        tree, parser = parse_file(source_code, extension)
        if tree is None:
            return []  # Unsupported extension or parse error — skip silently

        # Dispatch to language-specific extractor
        if extension == ".py":
            return self._scan_python(file_path, source_code, source_bytes, tree)
        elif extension in (".js", ".ts", ".jsx", ".tsx"):
            return self._scan_javascript(file_path, source_code, source_bytes, tree)
        elif extension == ".java":
            return self._scan_java(file_path, source_code, source_bytes, tree)
        elif extension == ".php":
            return self._scan_php(file_path, source_code, source_bytes, tree)
        elif extension in (".c", ".h"):
            return self._scan_c(file_path, source_code, source_bytes, tree, "c")
        elif extension in (".cpp", ".cc", ".cxx", ".hpp"):
            return self._scan_c(file_path, source_code, source_bytes, tree, "cpp")

        return []

    # ── Language-specific scanners ────────────────────────────────────────────

    def _scan_python(self, file_path: str, source_code: str,
                     source_bytes: bytes, tree) -> list[Finding]:
        """Run the full advanced SAST pipeline on a Python file."""
        findings = []

        # Step 1: Extract structured info (assignments, calls, functions)
        file_info = extract_python_info(tree, source_bytes)

        # Step 2: Run advanced taint analysis (SSA + dataflow + interprocedural + framework)
        taint_engine = TaintEngine(rules=self.rules["python"])
        taint_findings = taint_engine.analyze(file_info, file_path, source_code=source_code)

        # Step 3: Convert taint findings to Finding objects
        for tf in taint_findings:
            rule = self.rules["python"].get(tf.rule_id, {})
            if not rule:
                continue
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)

        # Step 4: Pattern-based rules (hardcoded secrets)
        secret_findings = self._detect_secrets(
            file_path, file_info, source_bytes, "python_secret_001", "python"
        )
        findings.extend(secret_findings)
        
        # Step 5: ReDoS patterns
        findings.extend(self._detect_redos(file_path, file_info))

        return findings

    def _scan_javascript(self, file_path: str, source_code: str,
                         source_bytes: bytes, tree) -> list[Finding]:
        """Run the full advanced SAST pipeline on a JavaScript/TypeScript file."""
        findings = []

        file_info = extract_js_info(tree, source_bytes)

        taint_engine = TaintEngine(rules=self.rules["javascript"])
        taint_findings = taint_engine.analyze(file_info, file_path, source_code=source_code)

        for tf in taint_findings:
            rule = self.rules["javascript"].get(tf.rule_id, {})
            if not rule:
                continue
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)

        secret_findings = self._detect_secrets(
            file_path, file_info, source_bytes, "js_secret_001", "javascript"
        )
        findings.extend(secret_findings)
        
        findings.extend(self._detect_redos(file_path, file_info))

        return findings

    def _scan_java(self, file_path: str, source_code: str,
                   source_bytes: bytes, tree) -> list[Finding]:
        """Run the full SAST pipeline on a Java file."""
        findings = []

        file_info = extract_java_info(tree, source_bytes)

        taint_engine = TaintEngine(rules=self.rules["java"])
        taint_findings = taint_engine.analyze(file_info, file_path)

        for tf in taint_findings:
            rule = self.rules["java"].get(tf.rule_id, {})
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)

        secret_findings = self._detect_secrets(
            file_path, file_info, source_bytes, "java_secret_001", "java"
        )
        findings.extend(secret_findings)
        
        findings.extend(self._detect_redos(file_path, file_info))

        return findings

    def _scan_php(self, file_path: str, source_code: str,
                  source_bytes: bytes, tree) -> list[Finding]:
        """Run the full SAST pipeline on a PHP file."""
        findings = []

        file_info = extract_php_info(tree, source_bytes)

        taint_engine = TaintEngine(rules=self.rules["php"])
        taint_findings = taint_engine.analyze(file_info, file_path)

        for tf in taint_findings:
            rule = self.rules["php"].get(tf.rule_id, {})
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)
            
        findings.extend(self._detect_redos(file_path, file_info))

        return findings

    def _scan_c(self, file_path: str, source_code: str,
                source_bytes: bytes, tree, language: str = "c") -> list[Finding]:
        """Run the full SAST pipeline on a C or C++ file."""
        findings = []

        file_info = extract_c_info(tree, source_bytes, language)

        lang_rules = self.rules.get(language, {})
        taint_engine = TaintEngine(rules=lang_rules)
        taint_findings = taint_engine.analyze(file_info, file_path)

        for tf in taint_findings:
            rule = lang_rules.get(tf.rule_id, {})
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)
            
        findings.extend(self._detect_redos(file_path, file_info))

        return findings

    # ── Cross-language helpers ────────────────────────────────────────────────

    def _detect_secrets(self, file_path: str, file_info, source_bytes: bytes,
                        rule_id: str, language: str) -> list[Finding]:
        """
        Detect hardcoded secrets using Shannon Entropy and Credential Patterns.
        """
        findings = []
        scanner = AdvancedSecretScanner()
        seen: set[tuple] = set()  # avoid duplicate findings on same line
        
        secret_rule = self.rules.get(language, {}).get(rule_id, {})
        patterns_section = secret_rule.get("secret_patterns", {}) if secret_rule else {}
        var_name_patterns = [p.lower() for p in patterns_section.get("variable_names", [])]
        exclude_values   = [v.lower() for v in patterns_section.get("exclude_values", [])]
        min_length       = patterns_section.get("min_value_length", 8)

        # 1. Advanced String Literal Scan (Layer 2A/2C)
        if hasattr(file_info, 'strings'):
            for string_literal in file_info.strings:
                secret_findings = scanner.scan_string_literal(string_literal.text, string_literal.line)
                for sf in secret_findings:
                    key = (file_path, sf.line, sf.rule_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    
                    findings.append(Finding(
                        id=f"{sf.rule_id}_{sf.line}_{hash(sf.matched_text) % 10000}",
                        rule_id=sf.rule_id,
                        vuln_class=sf.vuln_class,
                        file=file_path,
                        line=sf.line,
                        severity=sf.severity,
                        issue=sf.issue,
                        description=sf.message,
                        evidence=sf.matched_text,
                        taint_trace=[],
                        remediation=sf.remediation,
                        tool="devsecure_sast",
                        confidence=sf.confidence
                    ))

        # 2. Legacy Fallback: Variable Name Matching (for low entropy test keys)
        if secret_rule and hasattr(file_info, 'assignments'):
            for assignment in file_info.assignments:
                var_lower = assignment.target_name.lower().replace("-", "_").replace(".", "_")
                
                if not any(pattern in var_lower for pattern in var_name_patterns):
                    continue

                value = assignment.value_text.strip()
                if not (value.startswith('"') or value.startswith("'") or value.startswith('`')):
                    continue

                actual_value = value.strip('"\'`')
                if len(actual_value) < min_length or any(excl in actual_value.lower() for excl in exclude_values):
                    continue
                    
                key = (file_path, assignment.line, rule_id)
                if key in seen:
                    continue
                seen.add(key)
                
                findings.append(secret_finding(
                    file_path=file_path,
                    line=assignment.line,
                    var_name=assignment.target_name,
                    value_snippet=actual_value,
                    rule=secret_rule
                ))

        return findings


    def _detect_redos(self, file_path: str, file_info) -> list[Finding]:
        """
        Detect catastrophic backtracking ReDoS patterns in string literals.
        """
        findings = []
        scanner = AdvancedReDoSScanner()
        seen = set()

        if hasattr(file_info, 'strings'):
            for string_literal in file_info.strings:
                redos_findings = scanner.scan_regex(string_literal.text, string_literal.line)
                for rf in redos_findings:
                    key = (file_path, rf.line)
                    if key in seen:
                        continue
                    seen.add(key)
                    
                    findings.append(Finding(
                        id=f"{rf.rule_id}_{rf.line}_{hash(rf.matched_text) % 10000}",
                        rule_id=rf.rule_id,
                        vuln_class=rf.vuln_class,
                        file=file_path,
                        line=rf.line,
                        severity=rf.severity,
                        issue=rf.issue,
                        description=rf.message,
                        evidence=rf.matched_text,
                        taint_trace=[],
                        remediation=rf.remediation,
                        tool="devsecure_sast",
                        confidence=rf.confidence
                    ))
        return findings
