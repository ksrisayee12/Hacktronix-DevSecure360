"""
DevSecure360 — FastAPI Backend
Phase 0: Clean skeleton. No Bandit, Semgrep, or ZAP. Real engines wired in per phase.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Form, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import os, tempfile, shutil, zipfile, uuid, json
from datetime import datetime

from app.shared.types import ScanResult, ScanStatus, ScanType, Finding, Severity
from app.database.history_db import save_scan_result, get_scan_history
from app.utils.aggregator import compute_score

from app.scanner.sast.engine import SASTEngine
from app.scanner.remediation_engine import RemediationEngine
# Phase 3: from app.scanner.port.scanner import PortScanner
# Phase 4: from app.scanner.secrets.scanner import SecretScanner
# Phase 5: from app.scanner.dast.engine import DASTEngine

load_dotenv()

app = FastAPI(title=os.getenv("APP_NAME", "DevSecure360"), version="0.1.0")

origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()] or ["*"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.get("/")
def root():
    return {"app": "DevSecure360", "status": "online", "version": "0.1.0"}


@app.post("/scan/code")
async def scan_code(file: UploadFile = File(...)):
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, file.filename)
        with open(path, "wb") as f:
            f.write(await file.read())

        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as z:
                z.extractall(tmpdir)
            target = tmpdir
        else:
            target_dir = os.path.join(tmpdir, "uploaded")
            os.makedirs(target_dir, exist_ok=True)
            shutil.move(path, os.path.join(target_dir, os.path.basename(path)))
            target = target_dir

        result = SASTEngine().scan(target_path=target)

        save_scan_result("sast", {"findings": [_f(f) for f in result.findings], "score": result.score})
        return {"scan_id": result.scan_id, "status": result.status, "findings": [_f(f) for f in result.findings], "score": result.score, "target": result.target}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


class ExternalScanRequest(BaseModel):
    url: str

@app.post("/scan/external")
def scan_external(request: ExternalScanRequest):
    try:
        # Phase 5: result = DASTEngine().scan(target_url=request.url)
        result = _stub_result(ScanType.DAST, request.url)
        save_scan_result("dast", {"findings": result.findings, "score": result.score})
        return {"scan_id": result.scan_id, "status": result.status, "findings": [_f(f) for f in result.findings], "score": result.score}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class PortScanRequest(BaseModel):
    host: str
    port_range: str = "1-1024"

@app.post("/scan/port")
def scan_port(request: PortScanRequest):
    try:
        # Phase 3: result = PortScanner().scan(host=request.host, port_range=request.port_range)
        result = _stub_result(ScanType.PORT, request.host)
        save_scan_result("port", {"findings": result.findings, "score": result.score})
        return {"scan_id": result.scan_id, "status": result.status, "findings": [_f(f) for f in result.findings], "score": result.score}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history")
def history():
    return {"history": get_scan_history()}


class RemediateRequest(BaseModel):
    finding: Finding

@app.post("/scan/remediate")
def remediate_finding(request: RemediateRequest):
    try:
        fix = RemediationEngine.generate_fix(request.finding)
        return {"status": "success", "fix": fix}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/remediate-bulk")
def remediate_bulk(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    findings_json: str = Form(...),
    target_path: str = Form(...)
):
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, file.filename)
        with open(path, "wb") as f:
            f.write(file.file.read())

        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as z:
                z.extractall(tmpdir)
            target = tmpdir
        else:
            target_dir = os.path.join(tmpdir, "uploaded")
            os.makedirs(target_dir, exist_ok=True)
            shutil.move(path, os.path.join(target_dir, os.path.basename(path)))
            target = target_dir

        findings_data = json.loads(findings_json)
        original_target = target_path

        # Group findings by file
        from collections import defaultdict
        findings_by_file = defaultdict(list)
        from app.shared.types import Finding
        
        for f_data in findings_data:
            finding_obj = Finding(**{k: v for k, v in f_data.items() if k in Finding.__annotations__})
            orig_file_abs = finding_obj.file
            norm_orig = os.path.normpath(orig_file_abs) if orig_file_abs else ""
            norm_target = os.path.normpath(original_target) if original_target else ""

            if norm_orig and norm_target and norm_orig.lower().startswith(norm_target.lower()):
                findings_by_file[orig_file_abs].append(finding_obj)
            else:
                findings_by_file[orig_file_abs or "file"].append(finding_obj)

        total_files = len(findings_by_file)
        print(f"[AI Remediation] Total unique files to process: {total_files}", flush=True)

        for i, (orig_file_abs, file_findings) in enumerate(findings_by_file.items()):
            norm_orig = os.path.normpath(orig_file_abs) if orig_file_abs else ""
            norm_target = os.path.normpath(original_target) if original_target else ""

            if norm_orig and norm_target and norm_orig.lower().startswith(norm_target.lower()):
                rel_path = os.path.relpath(norm_orig, norm_target)
            else:
                rel_path = os.path.basename(norm_orig) if norm_orig else ""

            new_file_abs = os.path.normpath(os.path.join(target, rel_path)) if rel_path else target

            if not os.path.exists(new_file_abs):
                base = os.path.basename(norm_orig)
                found = None
                for root_d, _, files_f in os.walk(target):
                    if base and base in files_f:
                        found = os.path.join(root_d, base)
                        break
                if found:
                    new_file_abs = found
                else:
                    print(f"[AI Remediation] File not found in temp target: {new_file_abs}")
                    continue

            print(f"[AI Remediation] Processing file {i+1}/{total_files}: {os.path.basename(new_file_abs)} ({len(file_findings)} findings) ...", flush=True)

            with open(new_file_abs, "r", encoding="utf-8") as file_read:
                file_content = file_read.read()

            fix_snippet = RemediationEngine.generate_fix(file_findings, file_content)

            print(f"[AI Remediation] LLM Raw Output for {rel_path}:\n", "-"*40, f"\n{fix_snippet}\n", "-"*40, flush=True)
            
            # Extract code from markdown block
            import re
            code_blocks = re.findall(r'```(?:[a-zA-Z]*)\n(.*?)\n```', fix_snippet, re.DOTALL)
            if code_blocks:
                # The full patched file will be the longest code block
                patched_code = max(code_blocks, key=len).strip()
            else:
                patched_code = fix_snippet.strip()

            if patched_code:
                with open(new_file_abs, "w", encoding="utf-8") as file_write:
                    file_write.write(patched_code)

        # Zip the modified target directory
        zip_path = os.path.join(tmpdir, "remediated_code.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(target):
                for f in files:
                    file_path = os.path.join(root, f)
                    if file_path == zip_path:
                        continue
                    arcname = os.path.relpath(file_path, target)
                    zipf.write(file_path, arcname)

        background_tasks.add_task(shutil.rmtree, tmpdir, ignore_errors=True)
        return FileResponse(
            path=zip_path,
            filename="remediated_code.zip",
            media_type="application/zip"
        )
        
    except Exception as e:
        import traceback
        print(f"Error in remediate_bulk: {e}\n{traceback.format_exc()}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=str(e))



# ── Helpers ──────────────────────────────────────────────────────────────────

def _stub_result(scan_type: ScanType, target: str) -> ScanResult:
    """Placeholder result used until each engine is wired in."""
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        scan_type=scan_type,
        status=ScanStatus.COMPLETED,
        target=target,
        findings=[],
        score={"score": 100, "grade": "A", "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "max_cvss": 0},
        started_at=datetime.utcnow().isoformat(),
        completed_at=datetime.utcnow().isoformat(),
        error=None
    )


def _f(f: Finding) -> dict:
    """Convert Finding dataclass to JSON-serializable dict."""
    if isinstance(f, dict):
        return f
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "vuln_class": f.vuln_class,
        "scan_type": f.scan_type.value if hasattr(f.scan_type, "value") else f.scan_type,
        "file": f.file,
        "line": f.line,
        "url": f.url,
        "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
        "confidence": f.confidence,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "issue": f.issue,
        "description": f.description,
        "evidence": f.evidence,
        "taint_trace": [{"step": t.step, "line": t.line, "file": t.file, "description": t.description} for t in f.taint_trace] if f.taint_trace else [],
        "remediation": f.remediation,
        "tool": f.tool,
    }
