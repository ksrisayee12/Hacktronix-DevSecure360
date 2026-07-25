# backend/app/scanner/sast/engine.py
"""
DevSecure360 Proprietary SAST Engine — Enterprise Edition (Phase 1.7)

Performance Architecture:
    1. Inverted Sink Index — O(1) rule lookup per call (10-50x speedup vs naive loop)
    2. Content-Based Skip — Text pre-scan skips files with no sink keywords at all
    3. Parallel File Scanning — ThreadPoolExecutor scans N files simultaneously
    4. Incremental Scan Cache — Unchanged files return cached results instantly
    5. Pre-compiled Rule Patterns — Rule patterns compiled once at startup

Analysis Pipeline per file:
    1. File collection (by supported extension + config files)
    2. Content pre-scan (fast text scan — skip if no sink keywords)
    3. Cache lookup (return instantly if file unchanged and rules unchanged)
    4. AST parsing (tree-sitter — language-specific grammar)
    5. Structured info extraction (assignments, calls, functions, strings)
    6. Advanced Taint Analysis (SSA + CFG + Interprocedural, via TaintEngine)
    7. Pattern checks (secrets via entropy, ReDoS)
    8. Finding deduplication and assembly

Supported languages (Phase 1):
    Python (.py), JavaScript (.js, .ts, .jsx, .tsx),
    Java (.java), PHP (.php), C (.c, .h), C++ (.cpp, .cc, .cxx, .hpp)
"""

import os
import uuid
import hashlib
import json
import os
import uuid
import hashlib
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.shared.types import ScanResult, ScanStatus, ScanType, Finding, Severity

from .parser.base import parse_file, is_language_supported, supported_extensions
from .parser.python_pack import extract_python_info
from .parser.js_pack import extract_js_info
from .parser.java_pack import extract_java_info
from .parser.php_pack import extract_php_info
from .parser.c_pack import extract_c_info
from .parser.go_pack import extract_go_info
from .parser.csharp_pack import extract_csharp_info
from .cfg.builder import build_cfg
from .taint.engine import TaintEngine
from .taint.rule_index import RuleIndex
from .taint.scan_cache import ScanCache
from .rules.loader import load_rules, load_all_rules
from .taint.secrets import AdvancedSecretScanner, SecretFinding
from .taint.redos import AdvancedReDoSScanner, ReDoSFinding
from .reporter.formatter import taint_finding_to_finding, secret_finding
from .config_scanner import ConfigScanner

# Directories to skip when scanning
SKIP_DIRS = {
    'node_modules', '__pycache__', '.git', 'venv', '.venv',
    'dist', 'build', '.idea', '.vscode', 'target', 'bin', 'obj',
    'coverage', '.nyc_output', 'vendor', 'bower_components',
    '.cache', '.next', '.nuxt', 'out', 'public', 'static'
}

# Max worker threads for parallel file scanning
MAX_WORKERS = min(8, (os.cpu_count() or 2) * 2)

# Maximum file size to scan (skip huge minified/generated files)
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB


class SASTEngine:
    """
    DevSecure360 Enterprise SAST Engine.

    Detects 140+ vulnerability classes across 6 languages using:
    - Abstract Syntax Tree (AST) parsing
    - SSA-form dataflow taint analysis
    - CFG-backed worklist algorithm
    - 1-CFA interprocedural analysis
    - Shannon entropy secret detection
    - ReDoS catastrophic backtracking detection
    - Config file misconfiguration scanning
    - Inverted sink index for O(1) rule lookup (scales to 10,000+ rules)
    - Parallel file scanning
    - Incremental scan caching

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
            "go":         load_rules("go"),
            "csharp":     load_rules("csharp"),
        }

        # ── Performance Optimization 1: Pre-build Inverted Sink Index ──────────
        # Maps sink token → list of rules. O(1) lookup per call instead of O(rules).
        self._rule_indices: dict[str, RuleIndex] = {
            lang: RuleIndex(rules)
            for lang, rules in self.rules.items()
        }

        # ── Performance Optimization 2: Pre-compute sink keyword sets ──────────
        # Used for fast content-based file skip (before parsing).
        self._sink_keywords: dict[str, frozenset[str]] = {}
        for lang, rules in self.rules.items():
            all_sinks: set[str] = set()
            for rule in rules.values():
                for sink in rule.get("sinks", []):
                    # Extract just the final method name for fast text search
                    parts = sink.replace("::", ".").split(".")
                    all_sinks.update(p.lower() for p in parts if len(p) > 2)
            self._sink_keywords[lang] = frozenset(all_sinks)

        # ── Build a combined set of ALL sink keywords for generic pre-scan ─────
        self._all_sink_keywords: frozenset[str] = frozenset(
            kw for kwset in self._sink_keywords.values() for kw in kwset
        )

        total_rules = sum(len(r) for r in self.rules.values())
        total_tokens = sum(idx.indexed_tokens for idx in self._rule_indices.values())
        print(
            f"[SASTEngine] Rules loaded: "
            + ", ".join(f"{lang}={len(r)}" for lang, r in self.rules.items())
            + f" | Total: {total_rules} rules, {total_tokens} indexed tokens"
        )

    def scan(self, target_path: str, use_cache: bool = True, legacy_fallback: bool = False) -> ScanResult:
        """
        Scan a file or directory for security vulnerabilities.

        Args:
            target_path: Absolute path to a file or directory to scan.
            use_cache:   If True, use incremental scan cache (default True).
            legacy_fallback: If True, runs the noisy line-by-line fallback engine.

        Returns:
            ScanResult with all findings. Never raises — errors go into result.error.
        """
        self.legacy_fallback_enabled = legacy_fallback
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        all_findings: list[Finding] = []

        try:
            files = self._collect_files(target_path)
            print(f"[SASTEngine] Scanning {len(files)} file(s) in: {target_path}")

            # ── Performance Optimization 3: Incremental Scan Cache ─────────────
            cache_dir = target_path if os.path.isdir(target_path) else os.path.dirname(target_path)
            cache = ScanCache(self.rules, cache_dir=cache_dir) if use_cache else None

            # ── Performance Optimization 4: Parallel File Scanning ─────────────
            if len(files) > 1:
                findings_by_file = self._scan_parallel(files, cache)
            else:
                findings_by_file = {}
                for fp in files:
                    findings_by_file[fp] = self._scan_file_cached(fp, cache)

            for file_path, findings in findings_by_file.items():
                if findings:
                    print(f"[SASTEngine] {file_path}: {len(findings)} finding(s)")
                    all_findings.extend(findings)

            # Persist cache updates to disk
            if cache:
                cache.save()
                stats = cache.stats()
                if stats["total"] > 1:
                    print(f"[SASTEngine] Cache: {stats['hits']} hits / {stats['total']} files ({stats['hit_rate']} hit rate)")

            return ScanResult(
                scan_id=scan_id,
                scan_type=ScanType.SAST,
                status=ScanStatus.COMPLETED,
                target=target_path,
                findings=all_findings,
                score=None,  # computed by aggregator in main.py
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error=None
            )

        except Exception as e:
            import traceback
            print(f"[SASTEngine] Fatal error: {e}\n{traceback.format_exc()}")
            return ScanResult(
                scan_id=scan_id,
                scan_type=ScanType.SAST,
                status=ScanStatus.FAILED,
                target=target_path,
                findings=[],
                score=None,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )

    def _scan_parallel(self, files: list[str], cache) -> dict[str, list[Finding]]:
        """Scan multiple files in parallel using a thread pool."""
        results: dict[str, list[Finding]] = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {
                executor.submit(self._scan_file_cached, fp, cache): fp
                for fp in files
            }
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    results[file_path] = future.result()
                except Exception as e:
                    print(f"[SASTEngine] Warning: failed to scan {file_path}: {e}")
                    results[file_path] = []
        return results

    def _scan_file_cached(self, file_path: str, cache: ScanCache | None) -> list[Finding]:
        """Scan a file, using cache if available."""
        # ── Performance Optimization 3: Cache Lookup ────────────────────────────
        if cache:
            cached = cache.get(file_path)
            if cached is not None:
                # Deserialize cached finding dicts back to Finding objects
                return [_dict_to_finding(f) for f in cached]

        # Cache miss — do the full scan
        ext = os.path.splitext(file_path)[1].lower()
        try:
            findings = self._scan_file(file_path, ext)
        except Exception as e:
            print(f"[SASTEngine] Warning: failed to scan {file_path}: {e}")
            findings = []

        # Store results in cache
        if cache:
            cache.put(file_path, [_finding_to_dict(f) for f in findings])

        return findings

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
                        full_path = os.path.join(root, filename)
                        # ── Skip oversized files (minified JS, generated code) ──
                        try:
                            if os.path.getsize(full_path) <= MAX_FILE_SIZE_BYTES:
                                files.append(full_path)
                            else:
                                print(f"[SASTEngine] Skipping oversized file: {full_path}")
                        except OSError:
                            pass
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

        # ── Safety-First Content Pre-Scan ──────────────────────────────────────
        #
        # PURPOSE: Skip files that provably cannot have any findings.
        # SAFETY CONCERN: If we skip too aggressively, we cause false negatives
        # (missed findings). This is worse than false positives.
        #
        # POLICY (conservative — safety over speed):
        #   - NEVER skip a file that has string literals. Secrets (hardcoded API
        #     keys, passwords) have NO sink keywords. Any file with a string
        #     could contain a secret. We must always parse it.
        #   - Only skip if ALL three conditions are true:
        #       (a) No sink keywords found anywhere in the file text
        #       (b) No source keywords found anywhere in the file text
        #       (c) No string literals that could be secrets
        #
        # This is a very narrow skip condition. Only files that are purely
        # comments, whitespace, numeric constants, or type declarations
        # with zero string literals will be skipped. In practice this covers
        # mostly header files, interface definitions, and empty stubs.
        #
        source_lower = source_code.lower()
        has_potential_sink   = any(kw in source_lower for kw in self._all_sink_keywords)
        has_string_literals  = ('"' in source_code or "'" in source_code
                                or "`" in source_code or "=" in source_code)

        # Build a combined source keyword set (for source-only check)
        if not hasattr(self, "_all_source_keywords"):
            all_src: set[str] = set()
            for lang_rules in self.rules.values():
                for rule in lang_rules.values():
                    for src in rule.get("sources", []):
                        parts = src.replace("::", ".").split(".")
                        all_src.update(p.lower() for p in parts if len(p) > 2)
            self._all_source_keywords: frozenset[str] = frozenset(all_src)

        has_potential_source = any(kw in source_lower for kw in self._all_source_keywords)

        # Only skip if no sinks, no sources, AND no strings — all must be absent
        if not has_potential_sink and not has_potential_source and not has_string_literals:
            # This file is provably clean (no way to have taint, no secrets)
            return []  # Fast path — provably no findings possible

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
        elif extension in (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"):
            return self._scan_c(file_path, source_code, source_bytes, tree, "c" if extension in (".c", ".h") else "cpp")
        elif extension == ".go":
            return self._scan_go(file_path, source_code, source_bytes, tree)
        elif extension == ".cs":
            return self._scan_csharp(file_path, source_code, source_bytes, tree)

        return []

    # ── Language-specific scanners ─────────────────────────────────────────────

    def _scan_python(self, file_path: str, source_code: str,
                     source_bytes: bytes, tree) -> list[Finding]:
        """Run the full advanced SAST pipeline on a Python file."""
        findings = []

        file_info = extract_python_info(tree, source_bytes)

        taint_engine = TaintEngine(rules=self.rules["python"], rule_index=self._rule_indices.get("python"), legacy_fallback_enabled=self.legacy_fallback_enabled)
        taint_findings = taint_engine.analyze(file_info, file_path, source_code=source_code)

        for tf in taint_findings:
            rule = self.rules["python"].get(tf.rule_id, {})
            if not rule:
                continue
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)

        findings.extend(self._detect_secrets(file_path, file_info, source_bytes, "python_secret_001", "python"))
        findings.extend(self._detect_redos(file_path, file_info))
        return findings

    def _scan_javascript(self, file_path: str, source_code: str,
                         source_bytes: bytes, tree) -> list[Finding]:
        """Run the full advanced SAST pipeline on a JavaScript/TypeScript file."""
        findings = []

        file_info = extract_js_info(tree, source_bytes)

        taint_engine = TaintEngine(rules=self.rules["javascript"], rule_index=self._rule_indices.get("javascript"), legacy_fallback_enabled=self.legacy_fallback_enabled)
        taint_findings = taint_engine.analyze(file_info, file_path, source_code=source_code)

        for tf in taint_findings:
            rule = self.rules["javascript"].get(tf.rule_id, {})
            if not rule:
                continue
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)

        findings.extend(self._detect_secrets(file_path, file_info, source_bytes, "js_secret_001", "javascript"))
        findings.extend(self._detect_redos(file_path, file_info))
        return findings

    def _scan_java(self, file_path: str, source_code: str,
                   source_bytes: bytes, tree) -> list[Finding]:
        """Run the full SAST pipeline on a Java file."""
        findings = []

        file_info = extract_java_info(tree, source_bytes)

        taint_engine = TaintEngine(rules=self.rules["java"], rule_index=self._rule_indices.get("java"), legacy_fallback_enabled=self.legacy_fallback_enabled)
        taint_findings = taint_engine.analyze(file_info, file_path)

        for tf in taint_findings:
            rule = self.rules["java"].get(tf.rule_id, {})
            if not rule:
                continue
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)

        findings.extend(self._detect_secrets(file_path, file_info, source_bytes, "java_secret_001", "java"))
        findings.extend(self._detect_redos(file_path, file_info))
        return findings

    def _scan_php(self, file_path: str, source_code: str,
                  source_bytes: bytes, tree) -> list[Finding]:
        """Run the full SAST pipeline on a PHP file."""
        findings = []

        file_info = extract_php_info(tree, source_bytes)

        taint_engine = TaintEngine(rules=self.rules["php"], rule_index=self._rule_indices.get("php"), legacy_fallback_enabled=self.legacy_fallback_enabled)
        taint_findings = taint_engine.analyze(file_info, file_path)

        for tf in taint_findings:
            rule = self.rules["php"].get(tf.rule_id, {})
            if not rule:
                continue
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
        taint_engine = TaintEngine(rules=lang_rules, rule_index=self._rule_indices.get(language), legacy_fallback_enabled=self.legacy_fallback_enabled)
        taint_findings = taint_engine.analyze(file_info, file_path)

        for tf in taint_findings:
            rule = lang_rules.get(tf.rule_id, {})
            if not rule:
                continue
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)

        findings.extend(self._detect_secrets(file_path, file_info, source_bytes, "c_secret_001", language))
        return findings

    def _scan_go(self, file_path: str, source_code: str,
                 source_bytes: bytes, tree) -> list[Finding]:
        """Run the full SAST pipeline on a Go file."""
        findings = []

        file_info = extract_go_info(tree, source_bytes)

        taint_engine = TaintEngine(rules=self.rules["go"], rule_index=self._rule_indices.get("go"), legacy_fallback_enabled=self.legacy_fallback_enabled)
        taint_findings = taint_engine.analyze(file_info, file_path)

        for tf in taint_findings:
            rule = self.rules["go"].get(tf.rule_id, {})
            if not rule:
                continue
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)

        findings.extend(self._detect_secrets(file_path, file_info, source_bytes, "go_secret_001", "go"))
        return findings

    def _scan_csharp(self, file_path: str, source_code: str,
                     source_bytes: bytes, tree) -> list[Finding]:
        """Run the full SAST pipeline on a C# file."""
        findings = []

        file_info = extract_csharp_info(tree, source_bytes)

        taint_engine = TaintEngine(rules=self.rules["csharp"], rule_index=self._rule_indices.get("csharp"), legacy_fallback_enabled=self.legacy_fallback_enabled)
        taint_findings = taint_engine.analyze(file_info, file_path)

        for tf in taint_findings:
            rule = self.rules["csharp"].get(tf.rule_id, {})
            if not rule:
                continue
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)

        findings.extend(self._detect_secrets(file_path, file_info, source_bytes, "csharp_secret_001", "csharp"))
        return findings

    # ── Non-AST Scanners (Secrets, ReDoS) ─────────────────────────────────────────────────

    def _detect_secrets(self, file_path: str, file_info, source_bytes: bytes,
                        rule_id: str, language: str) -> list[Finding]:
        """Detect hardcoded secrets using Shannon Entropy and Credential Patterns."""
        findings = []
        scanner = AdvancedSecretScanner()
        seen: set[tuple] = set()

        secret_rule = self.rules.get(language, {}).get(rule_id, {})
        patterns_section = secret_rule.get("secret_patterns", {}) if secret_rule else {}
        var_name_patterns = [p.lower() for p in patterns_section.get("variable_names", [])]
        exclude_values   = [v.lower() for v in patterns_section.get("exclude_values", [])]
        min_length       = patterns_section.get("min_value_length", 8)

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
                        scan_type="sast",
                        file=file_path,
                        line=sf.line,
                        url=None,
                        severity=sf.severity,
                        confidence=sf.confidence,
                        issue=sf.issue,
                        description=sf.message,
                        evidence=sf.matched_text,
                        taint_trace=[],
                        remediation=sf.remediation,
                        tool="devsecure_sast"
                    ))

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
        """Detect catastrophic backtracking ReDoS patterns in string literals."""
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
                        scan_type="sast",
                        file=file_path,
                        line=rf.line,
                        url=None,
                        severity=rf.severity,
                        confidence=rf.confidence,
                        issue=rf.issue,
                        description=rf.message,
                        evidence=rf.matched_text,
                        taint_trace=[],
                        remediation=rf.remediation,
                        tool="devsecure_sast"
                    ))
        return findings


# ── Helper functions for cache serialization ───────────────────────────────────

def _finding_to_dict(f: Finding) -> dict:
    """Serialize a Finding to a JSON-compatible dict for caching."""
    # Serialize TaintStep objects if present
    raw_trace = getattr(f, "taint_trace", [])
    serialized_trace = []
    if raw_trace:
        from app.shared.types import TaintStep
        for step in raw_trace:
            if isinstance(step, TaintStep):
                serialized_trace.append({"step": step.step, "line": step.line, "file": step.file, "description": step.description})
            elif isinstance(step, dict):
                serialized_trace.append(step)

    return {
        "id": f.id, "rule_id": f.rule_id, "vuln_class": f.vuln_class,
        "scan_type": getattr(f, "scan_type", "sast"),
        "file": f.file, "line": f.line, "url": getattr(f, "url", None),
        "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
        "confidence": getattr(f, "confidence", "High"),
        "issue": f.issue, "description": getattr(f, "description", ""),
        "evidence": getattr(f, "evidence", ""), "taint_trace": serialized_trace,
        "remediation": f.remediation, "tool": f.tool,
        "cwe": getattr(f, "cwe", None),
        "cvss_score": getattr(f, "cvss_score", None),
        "cvss_vector": getattr(f, "cvss_vector", None),
    }


def _dict_to_finding(d: dict) -> Finding:
    """Deserialize a cached dict back to a Finding object."""
    raw_trace = d.get("taint_trace", [])
    deserialized_trace = []
    if raw_trace:
        from app.shared.types import TaintStep
        for step in raw_trace:
            if isinstance(step, dict):
                deserialized_trace.append(TaintStep(
                    step=step.get("step", 0), line=step.get("line", 0),
                    file=step.get("file", ""), description=step.get("description", "")
                ))
            else:
                deserialized_trace.append(step)

    return Finding(
        id=d.get("id", ""), rule_id=d.get("rule_id", ""),
        vuln_class=d.get("vuln_class", ""), scan_type=d.get("scan_type", "sast"),
        file=d.get("file", ""), line=d.get("line"),
        url=d.get("url"),
        severity=d.get("severity", "Medium"), confidence=d.get("confidence", "High"),
        issue=d.get("issue", ""), description=d.get("description", ""),
        evidence=d.get("evidence", ""), taint_trace=deserialized_trace,
        remediation=d.get("remediation", ""), tool=d.get("tool", "devsecure_sast"),
        cwe=d.get("cwe"), owasp=d.get("owasp"), cvss_score=d.get("cvss_score"), cvss_vector=d.get("cvss_vector"),
    )
