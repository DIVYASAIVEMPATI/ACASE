from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid
import time
from datetime import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from api.utils.scanner import run_scan
from api.database.db import (
    save_api_key, get_api_key, list_api_keys,
    save_scan, get_scan, get_scans_by_api_key
)

app = FastAPI(title="ACASE Security Scanner API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class APIKeyRequest(BaseModel):
    name: str
    email: str

class ScanRequest(BaseModel):
    target: str
    email: str

async def verify_api_key(x_api_key: str = Header(...)):
    key_data = get_api_key(x_api_key)
    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

def run_scan_background(scan_id, target, email, api_key):
    def callback(sid, status, progress, message):
        scan_data = get_scan(sid)
        if scan_data:
            scan_data["status"] = status
            scan_data["progress"] = progress
            scan_data["current_action"] = message
            save_scan(scan_data)
    
    results = run_scan(scan_id, target, email, callback=callback)
    
    scan_data = get_scan(scan_id)
    scan_data["status"] = results["status"]
    scan_data["completed_at"] = datetime.now().isoformat()
    scan_data["results"] = results
    save_scan(scan_data)

@app.get("/")
async def root():
    return {"service": "ACASE API", "version": "2.0.0", "status": "running"}

@app.post("/api/auth/generate-key")
async def generate_api_key(request: APIKeyRequest):
    api_key = f"acase_{uuid.uuid4().hex[:32]}"
    save_api_key(api_key, request.name, request.email)
    return {"api_key": api_key, "name": request.name, "message": "Save this key securely!"}

@app.get("/api/auth/keys")
async def list_keys():
    """List all API keys (for admin/debugging)"""
    keys = list_api_keys()
    return {"total": len(keys), "keys": keys}

@app.post("/api/scan/start", dependencies=[Depends(verify_api_key)])
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks, x_api_key: str = Header(...)):
    scan_id = f"scan_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    
    scan_data = {
        "scan_id": scan_id,
        "api_key": x_api_key,
        "target": request.target,
        "email": request.email,
        "status": "running",
        "progress": 0,
        "current_action": "Starting...",
        "started_at": datetime.now().isoformat()
    }
    save_scan(scan_data)
    
    background_tasks.add_task(run_scan_background, scan_id, request.target, request.email, x_api_key)
    
    return {"scan_id": scan_id, "status": "started"}

@app.get("/api/scan/{scan_id}/status", dependencies=[Depends(verify_api_key)])
async def get_scan_status(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/api/scan/{scan_id}/results", dependencies=[Depends(verify_api_key)])
async def get_scan_results(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.get("results") or {"message": "Scan in progress"}

@app.get("/api/scans/history", dependencies=[Depends(verify_api_key)])
async def get_scan_history(x_api_key: str = Header(...)):
    scans = get_scans_by_api_key(x_api_key)
    return {"total_scans": len(scans), "scans": scans}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
