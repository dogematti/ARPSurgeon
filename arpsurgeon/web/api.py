from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import queue
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from arpsurgeon.config import load_config
from arpsurgeon.engine import manager
from arpsurgeon.log import get_logger
from arpsurgeon.models import JobStatus
from arpsurgeon.storage import Database

logger = get_logger("api")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="ARPSurgeon Control Plane", docs_url="/docs", redoc_url="/redoc")

_start_time = time.monotonic()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR)

CAMPAIGNS_DIR = Path(__file__).parent.parent.parent / "templates" / "campaigns"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    elapsed = (time.monotonic() - start) * 1000
    logger.info("%s %s %d (%.1fms)", request.method, request.url.path,
                response.status_code, elapsed)
    return response

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

_config = load_config()
_api_key = _config.get("web", {}).get("api_key")

async def verify_api_key(
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
):
    if not _api_key:
        return
    # Support both header and query param (for SSE EventSource)
    bearer_token = None
    if authorization and authorization.startswith("Bearer "):
        bearer_token = authorization[7:]
    actual = bearer_token or token
    if not actual or actual != _api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

# ---------------------------------------------------------------------------
# Database & SSE
# ---------------------------------------------------------------------------

db = Database()
_event_queue: queue.Queue = queue.Queue(maxsize=1000)

def _on_event(evt):
    try:
        _event_queue.put_nowait(evt)
    except queue.Full:
        pass

db.add_event_listener(_on_event)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class JobRequest(BaseModel):
    args: Dict[str, Any]

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")

# --- Stats ---

@app.get("/api/v1/stats", dependencies=[Depends(verify_api_key)])
def get_stats():
    db_stats = db.get_stats()
    jobs = manager.list_jobs()
    active_jobs = sum(1 for j in jobs if j.status == "running")
    uptime = int(time.monotonic() - _start_time)
    return {
        **db_stats,
        "active_jobs": active_jobs,
        "total_jobs": len(jobs),
        "uptime_seconds": uptime,
    }

# --- Jobs ---

@app.get("/api/v1/jobs", response_model=list[JobStatus], dependencies=[Depends(verify_api_key)])
def list_jobs():
    return manager.list_jobs()

@app.get("/api/v1/jobs/{job_id}", dependencies=[Depends(verify_api_key)])
def get_job(job_id: str):
    job = manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

@app.post("/api/v1/jobs/{job_type}", dependencies=[Depends(verify_api_key)])
def start_job(job_type: str, request: JobRequest):
    try:
        job_id = manager.start_job(job_type, request.args)
        return {"job_id": job_id, "status": "started"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/v1/jobs/{job_id}", dependencies=[Depends(verify_api_key)])
def stop_job(job_id: str):
    if manager.stop_job(job_id):
        return {"status": "stopping"}
    raise HTTPException(status_code=404, detail="Job not found")

# --- Hosts ---

@app.get("/api/v1/hosts", dependencies=[Depends(verify_api_key)])
def get_hosts(
    limit: int = 100, offset: int = 0,
    search: Optional[str] = None,
    sort_by: str = "last_seen", sort_order: str = "DESC",
):
    items, total = db.get_hosts(limit=limit, offset=offset, search=search,
                                sort_by=sort_by, sort_order=sort_order)
    return {"items": items, "total": total, "limit": limit, "offset": offset}

@app.delete("/api/v1/hosts", dependencies=[Depends(verify_api_key)])
def clear_hosts():
    db.clear_hosts()
    return {"status": "cleared"}

# --- Events ---

@app.get("/api/v1/events", dependencies=[Depends(verify_api_key)])
def get_events(limit: int = 50, offset: int = 0, type: Optional[str] = None):
    items, total = db.get_events(limit=limit, offset=offset, event_type=type)
    return {"items": items, "total": total, "limit": limit, "offset": offset}

@app.delete("/api/v1/events", dependencies=[Depends(verify_api_key)])
def clear_events():
    db.clear_events()
    return {"status": "cleared"}

@app.get("/api/v1/events/stream", dependencies=[Depends(verify_api_key)])
async def event_stream():
    async def generate():
        while True:
            try:
                evt = _event_queue.get_nowait()
                yield f"data: {json.dumps(evt, default=str)}\n\n"
            except queue.Empty:
                yield ": keepalive\n\n"
                await asyncio.sleep(1)
    return StreamingResponse(generate(), media_type="text/event-stream")

# --- Topology ---

@app.get("/api/v1/topology", dependencies=[Depends(verify_api_key)])
def get_topology():
    hosts, _ = db.get_hosts(limit=500)
    refresh_stats = db.get_refresh_stats()

    nodes = []
    for h in hosts:
        label = h.get("ip", "?")
        if h.get("hostname"):
            label += f"\n{h['hostname']}"
        nodes.append({
            "id": h["ip"],
            "label": label,
            "title": f"MAC: {h.get('mac','?')}\nVendor: {h.get('vendor','?')}\nOS: {h.get('os','?')}",
            "shape": "box",
        })

    edges = []
    for r in refresh_stats:
        edges.append({
            "from": r["requester"],
            "to": r["target"],
            "arrows": "to",
            "label": f"{r.get('avg_interval', 0):.1f}s",
        })

    return {"nodes": nodes, "edges": edges}

# --- Export ---

@app.get("/api/v1/hosts/export", dependencies=[Depends(verify_api_key)])
def export_hosts(format: str = "csv"):
    hosts, _ = db.get_hosts(limit=10000)
    if format == "json":
        return hosts
    output = io.StringIO()
    fieldnames = ["ip", "mac", "hostname", "vendor", "os", "first_seen", "last_seen", "count"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for h in hosts:
        writer.writerow({k: h.get(k, "") for k in fieldnames})
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=hosts.csv"},
    )

@app.get("/api/v1/events/export", dependencies=[Depends(verify_api_key)])
def export_events(format: str = "csv"):
    events, _ = db.get_events(limit=10000)
    if format == "json":
        return events
    output = io.StringIO()
    fieldnames = ["id", "timestamp", "type", "data"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for e in events:
        row = dict(e)
        row["data"] = json.dumps(row.get("data", {}))
        writer.writerow({k: row.get(k, "") for k in fieldnames})
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )

# --- Profiles ---

@app.get("/api/v1/profiles", dependencies=[Depends(verify_api_key)])
def get_profiles():
    campaign_profiles = []
    if CAMPAIGNS_DIR.exists():
        for campaign_file in CAMPAIGNS_DIR.glob("*.yaml"):
            try:
                data = yaml.safe_load(campaign_file.read_text())
                name = data.get("name", campaign_file.stem)
                campaign_profiles.append({
                    "name": name,
                    "args": {"campaign_file": str(campaign_file)}
                })
            except Exception as e:
                logger.warning("Error loading campaign %s: %s", campaign_file, e)

    return {
        "campaign": campaign_profiles,
        "monitor": [
            {"name": "Standard Sentry (Default)", "args": {"storm_threshold": 200, "storm_window": 10, "verbose": True}},
            {"name": "Paranoid Watchdog (High Sensitivity)", "args": {"storm_threshold": 20, "storm_window": 5, "verbose": True}},
            {"name": "Passive Logger (Silent)", "args": {"verbose": False, "pcap_rotate_mb": 100}},
        ],
        "profile": [
            {"name": "Quick Recon (1 min)", "args": {"duration": 60}},
            {"name": "Asset Inventory (DHCP/mDNS Focus)", "args": {"duration": 600, "pcap_filter": "arp or (udp and (port 67 or port 5353))"}},
            {"name": "Full Traffic Dump (IP Capture)", "args": {"duration": 300, "pcap_rotate_mb": 500, "pcap_filter": "ip"}},
        ],
        "discover": [
            {"name": "Standard LAN Scan", "args": {"cidr": "192.168.1.0/24", "timeout": 2.0}},
            {"name": "Aggressive Fast Scan", "args": {"cidr": "192.168.1.0/24", "timeout": 0.5, "retry": 2}},
        ],
        "observe": [
            {"name": "ARP Refresh Observer (5 min)", "args": {"duration": 300, "pcap_filter": "arp"}},
            {"name": "Full Traffic Observer", "args": {"duration": 600}},
        ],
        "poison": [
            {"name": "Gateway Interception", "args": {"victim": ["192.168.1.10"], "gateway": "192.168.1.1", "forward": True}},
            {"name": "Stealth Poison (Slow Interval)", "args": {"victim": ["192.168.1.10"], "gateway": "192.168.1.1", "interval": 5.0, "jitter": 1.0, "forward": True}},
        ],
        "mitm": [
            {"name": "Full MITM (Poison + Relay + DNS)", "args": {"victim": ["192.168.1.10"], "gateway": "192.168.1.1", "forward": True}},
        ],
        "sever": [
            {"name": "Kill HTTP (Port 80)", "args": {"target": "192.168.1.10", "port": 80, "duration": 60}},
            {"name": "Kill HTTPS (Port 443)", "args": {"target": "192.168.1.10", "port": 443, "duration": 60}},
            {"name": "Kill SSH (Port 22)", "args": {"target": "192.168.1.10", "port": 22, "duration": 60}},
        ],
        "fuzz": [
            {"name": "Random Chaos (Low Rate)", "args": {"mode": "random", "rate": 10}},
            {"name": "Stress: ARP Opcode Storm", "args": {"mode": "arp_opcode", "rate": 50}},
            {"name": "Stress: MAC Flooding", "args": {"mode": "mac_flood", "rate": 500}},
        ],
        "dns-spoof": [
            {"name": "Redirect All to Self", "args": {"default_ip": "192.168.1.5", "ttl": 60}},
        ],
        "check": [
            {"name": "Check Single Host", "args": {"victim": ["192.168.1.10"], "ping": True}},
        ],
        "snapshot": [
            {"name": "Snapshot LAN", "args": {"cidr": "192.168.1.0/24", "output": "snapshot.json"}},
        ],
        "restore-snapshot": [
            {"name": "Restore from File", "args": {"input": "snapshot.json"}},
        ],
        "relay": [
            {"name": "Relay Traffic", "args": {"victim": ["192.168.1.10"], "gateway": "192.168.1.1"}},
        ],
        "restore": [
            {"name": "Restore ARP Tables", "args": {"victim": ["192.168.1.10"], "gateway": "192.168.1.1"}},
        ],
    }
