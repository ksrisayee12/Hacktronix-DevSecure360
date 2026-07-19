# backend/app/agent/normalizer.py

import json
import logging
import os
from typing import List, Dict, Any
import shutil

# Configure logger for this module with only file handler, no terminal logs
logger = logging.getLogger("normalizer")
logger.setLevel(logging.DEBUG)

# Clear existing handlers to avoid duplicate logs if reloaded
logger.handlers.clear()

# File handler to write logs to 'normalizer.log' inside agent folder
log_file_path = os.path.join(os.path.dirname(__file__), 'normalizer.log')
fh = logging.FileHandler(log_file_path)
fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(fh)

def normalize_severity(sev: str) -> str:
    """Normalize severity values to standard Low, Medium, High strings."""
    mapping = {
        'low': 'Low',
        'medium': 'Medium',
        'high': 'High',
        'info': 'Low'
    }
    return mapping.get(sev.strip().lower(), 'Low')

def normalize_file_path(path: str) -> str:
    """Normalize file path to consistent forward slash format and trim temp folders."""
    if not path:
        return ""
    # Replace backslashes with slash for consistency
    normalized = path.replace("\\", "/")
    # Remove temporary directories: example logic, adjust as needed
    parts = normalized.split('/')
    if "temp" in parts:
        temp_index = parts.index("temp")
        normalized = "/".join(parts[temp_index + 2:])  # Skip temp and subdir to actual file path
    return normalized

def generate_finding_id(tool: str, file_path: str, line: int, issue: str) -> str:
    """Generate a unique ID for each finding based on core info."""
    base = f"{tool}:{file_path}:{line}:{issue}"
    return base.encode('utf-8').hex()

def normalize_findings(raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize a list of scanner findings to a canonical schema:
    - id (unique)
    - tool (scanner name)
    - severity (standardized)
    - file_path (normalized)
    - start_line, end_line (for now same line if single line)
    - snippet (issue description)
    """
    normalized = []
    for finding in raw_findings:
        try:
            tool = finding.get("tool", "").lower()
            raw_path = finding.get("file", "") or finding.get("file_path", "")
            file_path = normalize_file_path(raw_path)
            line = finding.get("line", 0)
            issue = finding.get("issue", "").strip()
            severity_raw = finding.get("severity", "Low")
            severity = normalize_severity(severity_raw)

            if not issue or not file_path or not tool:
                logger.warning(f"Skipping incomplete finding: {finding}")
                continue

            finding_id = generate_finding_id(tool, file_path, line, issue)

            normalized.append({
                "id": finding_id,
                "tool": tool,
                "severity": severity,
                "file_path": file_path,
                "start_line": line,
                "end_line": line,
                "snippet": issue,
            })
        except Exception as e:
            logger.error(f"Error normalizing finding {finding}: {e}")

    logger.info(f"Normalized {len(normalized)} findings")
    return normalized

def read_raw_scan_history(json_path: str) -> List[Dict[str, Any]]:
    """
    Read only the first entry (latest scan) in the scan_history.json.
    Extract and return its 'findings' list only.
    """
    if not os.path.exists(json_path):
        logger.error(f"Scan history file not found: {json_path}")
        return []

    with open(json_path, 'r', encoding='utf-8') as f:
        try:
            raw_data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON file: {e}")
            return []

    # Choose only the first entry of the JSON array (index 0)
    if not raw_data or not isinstance(raw_data, list):
        logger.error("Scan history JSON is empty or not a list")
        return []

    first_block = raw_data[0]
    findings = first_block.get("findings", [])
    logger.info(f"Read {len(findings)} findings from the latest scan history block")
    return findings

def normalize_scan_history(json_path: str) -> List[Dict[str, Any]]:
    """
    Full workflow to read raw scan history from given JSON path
    and produce normalized findings list.
    Only processes the first index in the scan history.
    """
    raw_findings = read_raw_scan_history(json_path)
    normalized_findings = normalize_findings(raw_findings)
    return normalized_findings

if __name__ == "__main__":
    # Example run - adjust path as needed for local testing
    sample_path = os.path.join(os.path.dirname(__file__), "../database/scan_history.json")

    # Save normalized data as JSON file inside agent folder
    output_path = os.path.join(os.path.dirname(__file__), "normalized_findings.json")
    # In case you want to force removal of an old file (optional, but generally fine to overwrite directly)
    try:
        os.remove(output_path)
    except FileNotFoundError:
        pass
    normalized = normalize_scan_history(sample_path)
    with open(output_path, 'w', encoding='utf-8') as outf:
        json.dump(normalized, outf, indent=2)
    logger.info(f"Normalized findings saved to {output_path}")
