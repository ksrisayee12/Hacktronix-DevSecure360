"""
ReDoS (Regular Expression Denial of Service) Detector
Scans regular expression strings for catastrophic backtracking patterns.
"""

import re
from dataclasses import dataclass

@dataclass
class ReDoSFinding:
    rule_id: str = "advanced_redos_001"
    vuln_class: str = "ReDoS"
    severity: str = "High"
    issue: str = "Catastrophic Backtracking Regular Expression (ReDoS)"
    message: str = ""
    remediation: str = "Avoid nested quantifiers (e.g. `(a+)+`), overlapping alternations (e.g. `(a|a)+`), and unbounded overlapping character classes."
    line: int = 0
    confidence: str = "Medium"
    matched_text: str = ""


class AdvancedReDoSScanner:
    """Analyzes regex patterns for ReDoS vulnerabilities."""
    
    # Heuristics for ReDoS patterns
    REDOS_PATTERNS = [
        # Nested quantifiers: (a+)+, (a*)*, (a+)*, (a*)+
        re.compile(r'\([^)]*([+*]|\{\d+,?\d*\}).*?\)[+*]'),
        
        # Overlapping alternation: (a|a)+
        re.compile(r'\(([^|]+)\|\1\)[+*]'),
        
        # Multiple adjacent unbounded quantifiers matching similar groups: [a-zA-Z]+[a-z]+
        # (This is harder to catch statically without a full NFA engine, we'll keep it simple for now)
        re.compile(r'(?:\w\+|\.\*){2,}') 
    ]

    def scan_regex(self, regex_string: str, line: int) -> list[ReDoSFinding]:
        """Scans a regex string literal for ReDoS."""
        findings = []
        
        if len(regex_string) < 5 or len(regex_string) > 500:
            return findings
            
        # Clean up Javascript / Python regex delimiters
        clean_regex = regex_string
        if clean_regex.startswith('/') and clean_regex.rfind('/') > 0:
            # JS format: /pattern/flags
            clean_regex = clean_regex[1:clean_regex.rfind('/')]
        elif clean_regex.startswith('r"') or clean_regex.startswith("r'"):
            clean_regex = clean_regex[2:-1]
        elif clean_regex.startswith('"') or clean_regex.startswith("'"):
            clean_regex = clean_regex[1:-1]
            
        for pattern in self.REDOS_PATTERNS:
            match = pattern.search(clean_regex)
            if match:
                findings.append(ReDoSFinding(
                    message=f"Regex contains a pattern prone to catastrophic backtracking (ReDoS): `{clean_regex}`",
                    line=line,
                    matched_text=clean_regex
                ))
                break # Only one finding per regex
                
        return findings
