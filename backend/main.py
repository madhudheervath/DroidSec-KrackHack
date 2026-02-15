"""
DroidSec — APK Static Security Analyzer
Main FastAPI application.
"""
import json
import os
import uuid
import shutil
import logging
from pathlib import Path
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from core.decompiler import Decompiler
from core.manifest_analyzer import analyze_manifest
from core.code_scanner import scan_source_code
from core.owasp_mapper import aggregate_findings, analyze_permissions
from core.report_generator import save_report, generate_html_report, generate_json_report
from core.ai_analyzer import get_ai_analyzer, set_api_key
from rules.malware import analyze_malware_heuristics
from rules.entropy import analyze_entropy
from rules.network_config import analyze_network_config
from rules.signing import analyze_apk_signing
from rules.cloud_config import analyze_cloud_configs
from rules.deeplink import analyze_deeplinks
from rules.binary_protection import analyze_binary_protections
from rules.modern_heuristics import analyze_modern_heuristics
from utils.library_analyzer import analyze_libraries

# --- Config ---
BASE_DIR = os.path.dirname(__file__)

# Store runtime artifacts outside backend source tree by default.
# This prevents uvicorn --reload from restarting on every upload/report write.
DATA_ROOT = os.getenv("DROIDSEC_DATA_DIR", "/tmp/droidsec-runtime")
UPLOAD_DIR = os.path.join(DATA_ROOT, "uploads")
REPORT_DIR = os.path.join(DATA_ROOT, "reports")
LEGACY_REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("droidsec")

# --- App ---
app = FastAPI(
    title="DroidSec API",
    description="APK Static Security Analyzer — Detects vulnerabilities and maps to OWASP Mobile Top 10",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

decompiler = Decompiler()

# In-memory scan store (for hackathon simplicity)
scans = {}
active_scans = {}


def _report_dirs() -> List[str]:
    dirs = [REPORT_DIR]
    if LEGACY_REPORT_DIR != REPORT_DIR:
        dirs.append(LEGACY_REPORT_DIR)
    return dirs


def _find_report_file(scan_id: str, filename: str) -> Optional[str]:
    for report_dir in _report_dirs():
        path = os.path.join(report_dir, scan_id, filename)
        if os.path.exists(path):
            return path
    return None


@app.get("/")
def root():
    return {"name": "DroidSec", "version": "1.0.0", "status": "running"}


def _run_scan_pipeline(scan_id: str, apk_filename: str, apk_path: str) -> dict:
    """Run full scan synchronously; called from threadpool to keep event loop responsive."""
    # Step 1: Decompile
    logger.info(f"[{scan_id}] Decompiling...")
    decompile_result = decompiler.decompile(apk_path, scan_id)
    if not decompile_result["success"]:
        raise HTTPException(500, f"Decompilation failed: {decompile_result['errors']}")

    # Step 2: Analyze manifest
    logger.info(f"[{scan_id}] Analyzing manifest...")
    manifest_result = {"findings": [], "metadata": {}}
    if decompile_result["manifest_path"]:
        manifest_result = analyze_manifest(decompile_result["manifest_path"])

    # Step 3: Scan source code
    logger.info(f"[{scan_id}] Scanning source code...")
    scan_result = scan_source_code(
        source_dirs=decompile_result["source_dirs"],
        resource_dirs=decompile_result["resource_dirs"],
    )
    code_findings = scan_result["findings"]
    files_scanned = scan_result["files_scanned"]

    # Step 4: Analyze permissions
    logger.info(f"[{scan_id}] Analyzing permissions...")
    permission_findings = analyze_permissions(
        manifest_result.get("metadata", {}).get("permissions", [])
    )

    # Step 5: Analyze Malware Heuristics
    logger.info(f"[{scan_id}] Analyzing malware heuristics...")
    malware_findings = analyze_malware_heuristics(
        permissions=manifest_result.get("metadata", {}).get("permissions", []),
        metadata=manifest_result.get("metadata", {})
    )

    # Step 6: Entropy Analysis (detect hidden secrets)
    logger.info(f"[{scan_id}] Analyzing string entropy...")
    entropy_findings = analyze_entropy(decompile_result["source_dirs"])

    # Step 7: Network Security Config
    logger.info(f"[{scan_id}] Analyzing network security config...")
    apktool_dir = decompile_result.get("apktool_dir", "")
    network_findings = analyze_network_config(apktool_dir)

    # Step 8: APK Signing Analysis
    logger.info(f"[{scan_id}] Analyzing APK signing...")
    signing_findings = analyze_apk_signing(apk_path)

    # Step 9: Cloud/Firebase Misconfiguration
    logger.info(f"[{scan_id}] Checking cloud configurations...")
    cloud_findings = analyze_cloud_configs(
        source_dirs=decompile_result["source_dirs"],
        resource_dirs=decompile_result["resource_dirs"]
    )

    # Step 10: Deeplink & Intent Analysis
    logger.info(f"[{scan_id}] Analyzing deeplinks and intents...")
    deeplink_findings = analyze_deeplinks(decompile_result["manifest_path"])

    # Step 11: Binary Protection Analysis
    logger.info(f"[{scan_id}] Analyzing binary protections...")
    binary_findings = analyze_binary_protections(
        source_dirs=decompile_result["source_dirs"],
        apktool_dir=apktool_dir
    )

    # Step 12: Research-driven modern heuristic analysis
    logger.info(f"[{scan_id}] Running modern logic-gated heuristics...")
    modern_findings = analyze_modern_heuristics(
        source_dirs=decompile_result["source_dirs"],
        manifest_path=decompile_result.get("manifest_path"),
        resource_dirs=decompile_result["resource_dirs"],
    )

    # Step 13: Analyze Libraries (SCA)
    logger.info(f"[{scan_id}] Analyzing libraries...")
    detected_libs = analyze_libraries(decompile_result["source_dirs"])

    # Step 14: Aggregate ALL findings and score
    logger.info(f"[{scan_id}] Generating report...")
    all_extra_findings = (
        malware_findings + entropy_findings + network_findings +
        signing_findings + cloud_findings + deeplink_findings +
        binary_findings + modern_findings
    )
    report_data = aggregate_findings(
        manifest_findings=manifest_result["findings"],
        code_findings=code_findings,
        permission_findings=permission_findings,
        malware_findings=all_extra_findings,
        files_scanned=files_scanned
    )

    # Add metadata
    metadata = manifest_result.get("metadata", {})
    metadata["libraries"] = detected_libs
    report_data["metadata"] = metadata
    report_data["scan_id"] = scan_id
    report_data["apk_filename"] = apk_filename
    report_data["decompile_errors"] = decompile_result.get("errors", [])

    # Step 15: Save reports
    report_output_dir = os.path.join(REPORT_DIR, scan_id)
    save_report(report_data, report_output_dir, metadata.get("package", "unknown"))

    # Store in memory
    scans[scan_id] = report_data
    logger.info(f"[{scan_id}] Scan complete! Score: {report_data['security_score']['score']}/100")

    return report_data


@app.post("/api/scan")
async def scan_apk(file: UploadFile = File(...)):
    """
    Upload an APK and run a full security scan.
    Returns the complete security report.
    """
    if not file.filename.endswith(".apk"):
        raise HTTPException(400, "Only .apk files are supported")

    scan_id = str(uuid.uuid4())[:8]
    apk_path = os.path.join(UPLOAD_DIR, f"{scan_id}.apk")

    # Save uploaded file
    try:
        with open(apk_path, "wb") as f:
            content = await file.read()
            f.write(content)
        logger.info(f"[{scan_id}] Saved APK: {file.filename} ({len(content)} bytes)")
    except Exception as e:
        raise HTTPException(500, f"Failed to save file: {e}")

    active_scans[scan_id] = {
        "scan_id": scan_id,
        "name": file.filename,
        "started_at": datetime.utcnow().isoformat(),
        "status": "running",
    }
    try:
        report_data = await run_in_threadpool(_run_scan_pipeline, scan_id, file.filename, apk_path)
        return JSONResponse(content=report_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{scan_id}] Scan failed: {e}", exc_info=True)
        raise HTTPException(500, f"Scan failed: {str(e)}")
    finally:
        active_scans.pop(scan_id, None)
        # Cleanup APK (keep reports)
        if os.path.exists(apk_path):
            os.remove(apk_path)


@app.get("/api/report/{scan_id}")
def get_report(scan_id: str):
    """Get a previously generated report."""
    if scan_id in scans:
        return JSONResponse(content=scans[scan_id])

    json_path = _find_report_file(scan_id, "report.json")
    if json_path:
        with open(json_path) as f:
            return JSONResponse(content=json.load(f))

    raise HTTPException(404, "Report not found")


@app.get("/api/report/{scan_id}/html")
def get_html_report(scan_id: str):
    """Get the HTML report for a scan."""
    html_path = _find_report_file(scan_id, "report.html")
    if html_path:
        with open(html_path) as f:
            return HTMLResponse(content=f.read())
    raise HTTPException(404, "HTML report not found")


@app.get("/api/report/{scan_id}/download")
def download_report(scan_id: str):
    """Download the HTML report."""
    html_path = _find_report_file(scan_id, "report.html")
    if html_path:
        return FileResponse(
            html_path,
            media_type="text/html",
            filename=f"droidsec-report-{scan_id}.html",
        )
    raise HTTPException(404, "Report not found")


@app.get("/api/scans")
def list_scans():
    """List all completed scans."""
    results = []
    for sid, data in scans.items():
        results.append({
            "scan_id": sid,
            "filename": data.get("apk_filename", "unknown"),
            "score": data.get("security_score", {}).get("score", 0),
            "grade": data.get("security_score", {}).get("grade", "?"),
            "total_findings": data.get("total_findings", 0),
        })
    return results


# ============================================
# AI-Powered Analysis Endpoints
# ============================================

class AIConfigRequest(BaseModel):
    api_key: str

class AIChatRequest(BaseModel):
    message: str
    scan_id: str

class AIRemediateRequest(BaseModel):
    finding_index: int
    scan_id: str


@app.get("/api/ai/status")
def ai_status():
    """Check if AI features are available."""
    ai = get_ai_analyzer()
    model_info = "gemini-2.0-flash" if ai.provider == "gemini" else (ai.model_name if ai.provider == "groq" else None)
    return {
        "available": ai.is_available,
        "provider": ai.provider,
        "model": model_info,
        "message": "AI ready" if ai.is_available else "Set API key via POST /api/ai/config"
    }


@app.post("/api/ai/config")
def configure_ai(req: AIConfigRequest):
    """Set the Gemini API key."""
    try:
        set_api_key(req.api_key)
        ai = get_ai_analyzer()
        return {
            "success": ai.is_available,
            "message": "AI configured successfully" if ai.is_available else "Failed to initialize AI with provided key"
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to configure AI: {e}")


@app.post("/api/ai/analyze/{scan_id}")
async def ai_deep_analysis(scan_id: str):
    """Run AI-powered deep analysis on scan results."""
    ai = get_ai_analyzer()
    if not ai.is_available:
        raise HTTPException(400, "AI not configured. POST your Gemini API key to /api/ai/config first.")

    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")

    report_data = scans[scan_id]
    logger.info(f"[{scan_id}] Running AI deep analysis...")

    result = await ai.deep_analysis(report_data)
    return JSONResponse(content=result)


@app.post("/api/ai/chat")
async def ai_chat(req: AIChatRequest):
    """Interactive AI chat about scan results."""
    ai = get_ai_analyzer()
    if not ai.is_available:
        raise HTTPException(400, "AI not configured.")

    if req.scan_id not in scans:
        raise HTTPException(404, "Scan not found")

    response = await ai.chat(req.scan_id, req.message, scans[req.scan_id])
    return {"response": response}


@app.post("/api/ai/remediate")
async def ai_remediate(req: AIRemediateRequest):
    """Get AI-powered detailed remediation for a specific finding."""
    ai = get_ai_analyzer()
    if not ai.is_available:
        raise HTTPException(400, "AI not configured.")

    if req.scan_id not in scans:
        raise HTTPException(404, "Scan not found")

    findings = scans[req.scan_id].get("findings", [])
    if req.finding_index < 0 or req.finding_index >= len(findings):
        raise HTTPException(400, "Invalid finding index")

    finding = findings[req.finding_index]
    response = await ai.generate_remediation(finding)
    return {"remediation": response, "finding": finding.get("name", "Unknown")}




@app.get("/api/reports")
def get_reports():
    """List all available reports."""
    reports = []
    seen = set()
    for report_dir in _report_dirs():
        if not os.path.exists(report_dir):
            continue
        for scan_id in os.listdir(report_dir):
            if scan_id in seen:
                continue
            report_path = os.path.join(report_dir, scan_id, "report.json")
            if not os.path.exists(report_path):
                continue
            try:
                with open(report_path) as f:
                    data = json.load(f)
                ts = data.get("timestamp") or datetime.utcfromtimestamp(os.path.getmtime(report_path)).isoformat()
                reports.append({
                    "scan_id": scan_id,
                    "package": data.get("package", "unknown"),
                    "score": data.get("security_score", {}).get("score", 0),
                    "grade": data.get("security_score", {}).get("grade", "?"),
                    "timestamp": ts,
                    "filename": data.get("apk_filename", f"{scan_id}.apk"),
                    "findings_count": data.get("total_findings", 0),
                })
                seen.add(scan_id)
            except Exception:
                continue

    reports.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return reports


@app.get("/api/batch-status")
def get_batch_status():
    """Return active scans + latest completed scans for dashboard polling."""
    rows = []
    for s in active_scans.values():
        rows.append({
            "name": s.get("name", s.get("scan_id", "running")),
            "grade": "...",
            "score": "...",
            "error": False,
        })

    for report in get_reports()[:21]:
        rows.append({
            "name": report.get("filename") or report.get("package") or report.get("scan_id"),
            "grade": report.get("grade", "?"),
            "score": report.get("score", 0),
            "error": False,
        })
    return JSONResponse(content=rows[:21])

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
