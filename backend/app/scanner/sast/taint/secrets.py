"""
Advanced Secret Detection Engine (Layer 2A & 2C)

Uses Shannon entropy analysis and format-specific Regex patterns
to detect hardcoded secrets, API keys, and credentials, regardless
of variable names.
"""

import math
import re
from dataclasses import dataclass

@dataclass
class SecretFinding:
    rule_id: str
    vuln_class: str = "Hardcoded Secret"
    severity: str = "High"
    issue: str = "Hardcoded Secret/Credential Detected"
    message: str = ""
    remediation: str = "Store secrets securely in environment variables or a secrets manager like AWS Secrets Manager or HashiCorp Vault. Never hardcode credentials in source code."
    line: int = 0
    confidence: str = "High"
    matched_text: str = ""


class AdvancedSecretScanner:
    """Scans text for secrets using Regex and Entropy."""
    
    # Common format-specific patterns
    PATTERNS = [
        {"name": "AWS Access Key", "regex": re.compile(r'\bAKIA[0-9A-Z]{16}\b')},
        {"name": "GitHub Token", "regex": re.compile(r'\bghp_[0-9a-zA-Z]{36}\b')},
        {"name": "Slack Token", "regex": re.compile(r'\bxox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}\b')},
        {"name": "Google API Key", "regex": re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')},
        {"name": "Stripe Secret Key", "regex": re.compile(r'\bsk_(live|test)_[0-9a-zA-Z]{24}\b')},
        {"name": "SendGrid API Key", "regex": re.compile(r'\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b')},
        {"name": "Private Key PEM", "regex": re.compile(r'-----BEGIN (RSA )?PRIVATE KEY-----')},
        {"name": "SSH Private Key", "regex": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----')},
        {"name": "JSON Web Token (JWT)", "regex": re.compile(r'\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-\+]+={0,2}\b')},
    ]

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string (in bits per character)."""
        if not data:
            return 0.0
        entropy = 0.0
        counts = {}
        for char in data:
            counts[char] = counts.get(char, 0) + 1
        
        length = len(data)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def is_likely_secret(s: str) -> bool:
        """Check if a string is a high-entropy secret, filtering false positives."""
        if len(s) < 16 or len(s) > 256:
            return False
        
        # Filter common non-secret high-entropy strings
        lower_s = s.lower()
        if "http://" in lower_s or "https://" in lower_s:
            return False
        if "<?xml" in lower_s or "<html" in lower_s:
            return False
        
        # Check entropy (standard threshold for secrets is ~4.5)
        # Hex strings have lower max entropy (log2(16) = 4), Base64 has higher (log2(64) = 6)
        entropy = AdvancedSecretScanner.shannon_entropy(s)
        
        # Adjust threshold based on character set
        is_hex = all(c in '0123456789abcdefABCDEF-' for c in s)
        threshold = 3.5 if is_hex else 4.5
        
        # Require a mix of character types for non-hex strings to reduce FPs
        if not is_hex:
            has_upper = any(c.isupper() for c in s)
            has_lower = any(c.islower() for c in s)
            has_digit = any(c.isdigit() for c in s)
            if not (has_upper and has_lower and has_digit):
                # Increase threshold if it doesn't look like a standard random token
                threshold = 5.0
                
        return entropy >= threshold

    def scan_string_literal(self, literal_text: str, line: int) -> list[SecretFinding]:
        """Scans a single string literal for secrets."""
        findings = []
        
        # Clean up quotes if present
        clean_text = literal_text
        if len(clean_text) >= 2 and clean_text[0] in ('"', "'", "`") and clean_text[-1] == clean_text[0]:
            clean_text = clean_text[1:-1]
            
        # 1. Check strict regex patterns
        for pattern in self.PATTERNS:
            if pattern["regex"].search(clean_text):
                findings.append(SecretFinding(
                    rule_id="advanced_secret_pattern",
                    issue=f"Hardcoded {pattern['name']} detected",
                    message=f"Found a hardcoded {pattern['name']} matching a known credential format.",
                    line=line,
                    matched_text=clean_text[:100] + "..." if len(clean_text) > 100 else clean_text
                ))
                return findings # Stop after first strict match to avoid double reporting
                
        # 2. Check Entropy
        if self.is_likely_secret(clean_text):
            findings.append(SecretFinding(
                rule_id="advanced_secret_entropy",
                issue="High Entropy Secret Detected",
                message=f"Found a string literal with high entropy ({self.shannon_entropy(clean_text):.2f}), indicating a likely hardcoded secret or token.",
                line=line,
                confidence="Medium", # Entropy is less certain than regex
                matched_text=clean_text[:100] + "..." if len(clean_text) > 100 else clean_text
            ))

        return findings
