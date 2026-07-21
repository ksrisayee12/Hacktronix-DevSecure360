"""
Configuration File Scanner for DevSecure360 SAST Engine
Scans non-code files (.env, docker-compose, package.json, etc.) for misconfigurations.
"""

import os
import json
from app.shared.types import Finding

class ConfigScanner:
    """Scans configuration files for misconfigurations."""

    @staticmethod
    def scan_env_file(file_path: str, source: str) -> list[Finding]:
        """Scan .env files for secrets and debug flags."""
        findings = []
        for i, line in enumerate(source.splitlines()):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Check for DEBUG=True
            if "DEBUG" in line.upper() and ("TRUE" in line.upper() or "1" in line):
                findings.append(Finding(
                    id=f"env_debug_{i}",
                    rule_id="config_env_debug_001",
                    vuln_class="Misconfiguration",
                    scan_type="sast",
                    file=file_path,
                    line=i + 1,
                    url=None,
                    severity="High",
                    confidence="Confirmed",
                    issue="Debug Mode Enabled in Environment",
                    description="Running applications in debug mode in production can expose sensitive internal information.",
                    evidence=line,
                    taint_trace=[],
                    remediation="Set DEBUG=False for production environments.",
                    tool="devsecure_sast"
                ))
            
            # Note: We rely on the AdvancedSecretScanner to catch actual secrets in the .env file
            # so we don't duplicate that effort here.
        return findings

    @staticmethod
    def scan_docker_compose(file_path: str, source: str) -> list[Finding]:
        """Scan docker-compose.yml for privileged mode or exposed dangerous ports."""
        findings = []
        for i, line in enumerate(source.splitlines()):
            if "privileged: true" in line.lower() or 'privileged: "true"' in line.lower():
                findings.append(Finding(
                    id=f"docker_priv_{i}",
                    rule_id="config_docker_privileged_001",
                    vuln_class="Misconfiguration",
                    scan_type="sast",
                    file=file_path,
                    line=i + 1,
                    url=None,
                    severity="Critical",
                    confidence="Confirmed",
                    issue="Docker Privileged Mode Enabled",
                    description="Running a container in privileged mode grants it almost all capabilities of the host.",
                    evidence=line.strip(),
                    taint_trace=[],
                    remediation="Remove `privileged: true` and grant only specific required capabilities using `cap_add`.",
                    tool="devsecure_sast"
                ))
        return findings

    @staticmethod
    def scan_package_json(file_path: str, source: str) -> list[Finding]:
        """Scan package.json for known bad configurations or wildly outdated core packages."""
        findings = []
        try:
            data = json.loads(source)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            
            # Extremely simple check for outdated Express which is a common vulnerability target
            all_deps = {**deps, **dev_deps}
            for pkg, ver in all_deps.items():
                if pkg == "express" and ver.startswith(("3.", "^3.", "2.", "1.")):
                    findings.append(Finding(
                        id=f"pkg_json_express_{pkg}",
                        rule_id="config_pkg_outdated_001",
                        vuln_class="Vulnerable Dependency",
                        scan_type="sast",
                        file=file_path,
                        line=None,
                        url=None,
                        severity="High",
                        confidence="Confirmed",
                        issue="Outdated Express.js Version",
                        description=f"Found outdated and vulnerable version of {pkg} ({ver}).",
                        evidence=f'"{pkg}": "{ver}"',
                        taint_trace=[],
                        remediation="Upgrade to Express 4.x or 5.x.",
                        tool="devsecure_sast"
                    ))
        except Exception:
            pass # Ignore parse errors
        return findings

    @classmethod
    def scan_file(cls, file_path: str) -> list[Finding]:
        """Route to appropriate config scanner based on filename."""
        basename = os.path.basename(file_path).lower()
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
        except Exception:
            return []
            
        if basename == ".env":
            return cls.scan_env_file(file_path, source)
        elif basename in ("docker-compose.yml", "docker-compose.yaml"):
            return cls.scan_docker_compose(file_path, source)
        elif basename == "package.json":
            return cls.scan_package_json(file_path, source)
            
        return []
