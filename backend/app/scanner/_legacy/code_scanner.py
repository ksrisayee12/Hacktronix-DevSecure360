import os
import json
import subprocess
import shutil
import tempfile
from typing import List, Dict
import locale

try:
    locale.setlocale(locale.LC_ALL, 'C.UTF-8')
except locale.Error:
    try:
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    except locale.Error:
        pass

os.environ.update({
    "PYTHONUTF8": "1",
    "PYTHONIOENCODING": "utf-8",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
})

def run_bandit_scan(target_path: str) -> Dict:
    if not shutil.which("bandit"):
        return {"errors": "Bandit not installed or not found in PATH"}
    cmd = ["bandit", "-r", target_path, "-f", "json"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        out = proc.stdout or "{}"
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"errors": "Bandit produced invalid JSON", "stdout": out, "stderr": proc.stderr}
    except subprocess.TimeoutExpired:
        return {"errors": "Bandit scan timed out"}
    except Exception as e:
        return {"errors": str(e)}

def run_semgrep_scan(target_dir: str) -> list:
    env = os.environ.copy()
    env.update({
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    })

    def _try_semgrep(cmd: List[str]) -> List[Dict]:
        try:
            print(f"[semgrep] running: {' '.join(cmd)}")
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                timeout=600
            )

            if proc.returncode not in (0, 1):
                print("[semgrep] non-OK return:", proc.returncode)
                print("[semgrep] stderr snippet:", (proc.stderr or "")[:300])

            raw = (proc.stdout or "").strip()
            if not raw:
                raw = (proc.stderr or "").strip()

            if not raw:
                print("[semgrep] no output at all")
                return []

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                start, end = raw.find("{"), raw.rfind("}")
                if start != -1 and end != -1 and end > start:
                    snippet = raw[start:end+1]
                    data = json.loads(snippet)
                else:
                    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", prefix="semgrep_raw_")
                    tf.write(raw.encode("utf-8", errors="replace"))
                    tf.close()
                    print(f"[semgrep] Invalid output saved to {tf.name}")
                    return []

            findings = []
            for item in data.get("results", []):
                file_path = item.get("path") or "unknown"

                extra = item.get("extra", {})
                issue_msg = extra.get("message") or item.get("check_id") or "No description provided"

                severity = extra.get("severity") or "Medium"
                if isinstance(severity, str):
                    sev_low = severity.lower()
                    if "error" in sev_low or "high" in sev_low:
                        severity = "High"
                    elif "warn" in sev_low or "medium" in sev_low:
                        severity = "Medium"
                    elif "info" in sev_low or "low" in sev_low:
                        severity = "Low"
                    else:
                        severity = "Medium"


                findings.append({
                    "file": file_path,
                    "issue": issue_msg or "No description provided",
                    "severity": severity,
                    "tool": "semgrep"
                })

            print(f"[semgrep] Parsed {len(findings)} findings")
            return findings

        except Exception as e:
            print("[semgrep] exception:", e)
            return []

    attempts = [
        ["semgrep", "scan", "--config", "p/default", "--config", "p/ci", "--json", target_dir],
        ["semgrep", "scan", "--config", "p/security-audit", "--config", "p/ci", "--json", target_dir],
        ["semgrep", "scan", "--config", "auto", "--json", target_dir],
    ]

    for cmd in attempts:
        res = _try_semgrep(cmd)
        if res is not None and len(res) > 0:
            return res
        if res == []:
            return []

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    local_rules = os.path.join(root, "local_semgrep_rules.yml")
    if os.path.exists(local_rules):
        res = _try_semgrep(["semgrep", "scan", "--config", local_rules, "--json", target_dir])
        if res is not None:
            return res

    print("[semgrep] all attempts exhausted, returning []")
    return []

def run_code_scan(target_dir: str) -> list:
    results = []

    print(">>> Starting Bandit scan")
    results_bandit = run_bandit_scan(target_dir)
    print(">>> Bandit done")

    print(">>> Starting Semgrep scan")
    results_semgrep = run_semgrep_scan(target_dir)
    print(">>> Semgrep done")

    if isinstance(results_bandit, dict) and "results" in results_bandit:
        results.extend(results_bandit["results"])
    elif isinstance(results_bandit, list):
        results.extend(results_bandit)

    if isinstance(results_semgrep, list):
        results.extend(results_semgrep)
    elif isinstance(results_semgrep, dict) and "results" in results_semgrep:
        results.extend(results_semgrep["results"])

    print(f">>> Total findings: {len(results)}")
    return results

def standardize_code_results(bandit_json: dict, semgrep_json: list | dict) -> list[dict]:
    results = []

    if isinstance(bandit_json, dict) and "results" in bandit_json:
        for r in bandit_json["results"]:
            results.append({
                "tool": "bandit",
                "file": r.get("filename", "unknown"),
                "line": r.get("line_number"),
                "issue": r.get("issue_text", "No description provided"),
                "severity": map_bandit_severity(r.get("issue_severity")),
            })
    elif "errors" in bandit_json:
        results.append({
            "tool": "bandit",
            "file": None,
            "issue": bandit_json["errors"],
            "severity": "Low",
        })

    if isinstance(semgrep_json, list):
        for r in semgrep_json:
            results.append({
                "tool": "semgrep",
                "file": r.get("file", "unknown"),
                "issue": r.get("issue", "No description provided"),
                "severity": map_semgrep_severity(r.get("severity")),
            })
    elif isinstance(semgrep_json, dict) and "results" in semgrep_json:
        for r in semgrep_json["results"]:
            results.append({
                "tool": "semgrep",
                "file": r.get("path", "unknown"),
                "issue": r.get("extra", {}).get("message", "No description provided"),
                "severity": map_semgrep_severity(r.get("extra", {}).get("severity")),
            })
    elif isinstance(semgrep_json, dict) and "errors" in semgrep_json:
        results.append({
            "tool": "semgrep",
            "file": None,
            "issue": semgrep_json["errors"],
            "severity": "Low",
        })

    cleaned = [r for r in results if r.get("file") not in (None, "null", "")]
    return cleaned

def map_bandit_severity(level: str) -> str:
    if not level:
        return "Low"
    level = str(level).lower()
    if "high" in level:
        return "High"
    if "med" in level:
        return "Medium"
    return "Low"


def map_semgrep_severity(sev: dict | str) -> str:
    if not sev:
        return "Medium"
    if isinstance(sev, dict):
        sev = sev.get("severity", "")
    sev = str(sev).lower()
    if "error" in sev or "high" in sev:
        return "High"
    if "warn" in sev or "medium" in sev:
        return "Medium"
    if "info" in sev or "low" in sev:
        return "Low"
    return "Medium"
