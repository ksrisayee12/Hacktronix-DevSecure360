from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os, tempfile, shutil, zipfile

from pydantic import BaseModel

from app.scanner.code_scanner import run_bandit_scan, run_semgrep_scan, standardize_code_results
from app.scanner.external_scanner import trigger_zap_scan, parse_zap_alerts
from app.utils.aggregator import compute_score
from app.database.history_db import save_scan_result, get_scan_history

# NEW: import the agent pipeline
from app.agent.agent import main as run_agent_pipeline


load_dotenv()
app = FastAPI(title=os.getenv("APP_NAME", "DevSecure360"))

origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:3000")
origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
if not origins:
    origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"msg": "DevSecure360 API online"}


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

        bandit_json = run_bandit_scan(target)
        semgrep_json = run_semgrep_scan(target)

        findings = standardize_code_results(bandit_json, semgrep_json)

        score = compute_score(findings)

        result = {"findings": findings, "score": score}
        save_scan_result("code", result)
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    # finally:
    #     shutil.rmtree(tmpdir, ignore_errors=True)


class ExternalScanRequest(BaseModel):
    url: str


@app.post("/scan/external")
def scan_external(request: ExternalScanRequest):
    url = request.url
    try:
        zap_resp = trigger_zap_scan(url)
        findings = parse_zap_alerts(zap_resp)
        score = compute_score(findings)

        result = {"findings": findings, "score": score}
        save_scan_result("external", result)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history")
def history():
    return {"history": get_scan_history()}


# NEW: endpoint to run the agent pipeline after a code scan
@app.post("/agent/run")
def run_agent():
    """
    Trigger the full agent pipeline:
    - normalize latest scan history
    - build prompts
    - call Gemini to patch vulnerable files
    """
    try:
        run_agent_pipeline()
        return {"status": "ok", "message": "Agent pipeline completed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent pipeline failed: {e}")
