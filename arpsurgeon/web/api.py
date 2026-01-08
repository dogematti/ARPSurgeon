from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from arpsurgeon.engine import manager
from arpsurgeon.models import JobStatus
from arpsurgeon.storage import Database

app = FastAPI(title="ARPSurgeon Control Plane")

# Get absolute path to static files
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

db = Database()

class JobRequest(BaseModel):
    args: Dict[str, Any]

@app.get("/")
def read_root():
    return {"message": "ARPSurgeon API is running. Visit /static/index.html"}

@app.get("/api/v1/jobs", response_model=list[JobStatus])
def list_jobs():
    return manager.list_jobs()

@app.post("/api/v1/jobs/{job_type}")
def start_job(job_type: str, request: JobRequest):
    try:
        job_id = manager.start_job(job_type, request.args)
        return {"job_id": job_id, "status": "started"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/v1/jobs/{job_id}")
def stop_job(job_id: str):
    if manager.stop_job(job_id):
        return {"status": "stopping"}
    raise HTTPException(status_code=404, detail="Job not found")

@app.get("/api/v1/hosts")
def get_hosts():
    return db.get_hosts()

@app.get("/api/v1/events")
def get_events(limit: int = 50):
    return db.get_events(limit=limit)

@app.get("/api/v1/profiles")
def get_profiles():
    return {
        "monitor": [
            {
                "name": "Standard Sentry (Default)", 
                "args": {"storm_threshold": 200, "storm_window": 10, "verbose": True}
            },
            {
                "name": "Paranoid Watchdog (High Sensitivity)", 
                "args": {"storm_threshold": 20, "storm_window": 5, "verbose": True}
            },
            {
                "name": "Passive Logger (Silent)", 
                "args": {"verbose": False, "pcap_rotate_mb": 100}
            },
        ],
        "profile": [
            {
                "name": "Quick Recon (1 min)", 
                "args": {"duration": 60}
            },
            {
                "name": "Asset Inventory (DHCP/mDNS Focus)", 
                "args": {"duration": 600, "pcap_filter": "arp or (udp and (port 67 or port 5353))"}
            },
            {
                "name": "Full Traffic Dump (IP Capture)", 
                "args": {"duration": 300, "pcap_rotate_mb": 500, "pcap_filter": "ip"}
            },
        ],
        "discover": [
            {
                "name": "Standard LAN Scan",
                "args": {"cidr": "192.168.1.0/24", "timeout": 2.0}
            },
            {
                "name": "Aggressive Fast Scan",
                "args": {"cidr": "192.168.1.0/24", "timeout": 0.5, "retry": 2}
            }
        ],
        "poison": [
            {
                "name": "Gateway Interception", 
                "args": {"victim": ["192.168.1.10"], "gateway": "192.168.1.1", "forward": True}
            },
            {
                "name": "Stealth Poison (Slow Interval)", 
                "args": {"victim": ["192.168.1.10"], "gateway": "192.168.1.1", "interval": 5.0, "jitter": 1.0, "forward": True}
            },
        ],
        "mitm": [
            {
                "name": "Full MITM (Poison + Relay + DNS)",
                "args": {
                    "victim": ["192.168.1.10"], 
                    "gateway": "192.168.1.1", 
                    "forward": True,
                    "dns_spoof": True,
                    "dns_hosts_file": "hosts.txt"
                }
            }
        ],
        "sever": [
            {
                "name": "Kill HTTP (Port 80)", 
                "args": {"target": "192.168.1.10", "port": 80, "duration": 60}
            },
            {
                "name": "Kill HTTPS (Port 443)", 
                "args": {"target": "192.168.1.10", "port": 443, "duration": 60}
            },
            {
                "name": "Kill SSH (Port 22)", 
                "args": {"target": "192.168.1.10", "port": 22, "duration": 60}
            },
        ],
        "fuzz": [
            {
                "name": "Random Chaos (Low Rate)", 
                "args": {"mode": "random", "rate": 10}
            },
            {
                "name": "Stress: ARP Opcode Storm", 
                "args": {"mode": "arp_opcode", "rate": 50}
            },
            {
                "name": "Stress: MAC Flooding", 
                "args": {"mode": "mac_flood", "rate": 500}
            },
        ],
        "dns-spoof": [
            {
                "name": "Redirect All to Self",
                "args": {"default_ip": "192.168.1.5", "ttl": 60}
            }
        ]
    }
