"""
DevSecure360 — FastAPI Backend
Phase 0: Clean skeleton. No Bandit, Semgrep, or ZAP. Real engines wired in per phase.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import os, tempfile, shutil, zipfile, uuid
from datetime import datetime

from app.shared.types import ScanResult, ScanStatus, ScanType, Finding, Severity
from app.database.history_db import save_scan_result, get_scan_history
from app.utils.aggregator import compute_score

# Phase 1: from app.scanner.sast.engine import SASTEngine
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

        # Phase 1: result = SASTEngine().scan(target_path=target)
        result = _stub_result(ScanType.SAST, target)

        save_scan_result("sast", {"findings": result.findings, "score": result.score})
        return {"scan_id": result.scan_id, "status": result.status, "findings": [_f(f) for f in result.findings], "score": result.score}

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
