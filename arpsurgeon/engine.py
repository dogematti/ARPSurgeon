from __future__ import annotations

import argparse
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional

from arpsurgeon.campaign import run_campaign
from arpsurgeon.models import JobStatus
from arpsurgeon.observe import monitor, observe, profile

def _adapter_monitor(args: Dict[str, Any], stop_event: threading.Event) -> None:
    # Extract args with defaults matching CLI
    monitor(
        iface=args.get("iface"),
        duration=args.get("duration"), # Duration can still enforce max time
        jsonl_path=args.get("jsonl"),
        pcap_path=args.get("pcap"),
        pcap_filter=args.get("pcap_filter", ""), # We might need logic to build filter
        storm_threshold=args.get("storm_threshold", 200),
        storm_window=args.get("storm_window", 10),
        pcap_rotate_mb=args.get("pcap_rotate_mb"),
        pcap_rotate_seconds=args.get("pcap_rotate_seconds"),
        verbose=args.get("verbose", False),
        stop_event=stop_event
    )

def _adapter_profile(args: Dict[str, Any], stop_event: threading.Event) -> None:
    profile(
        iface=args.get("iface"),
        duration=args.get("duration"),
        oui_file=args.get("oui_file"),
        json_path=args.get("json"),
        jsonl_path=args.get("jsonl"),
        pcap_path=args.get("pcap"),
        pcap_filter=args.get("pcap_filter", ""),
        pcap_rotate_mb=args.get("pcap_rotate_mb"),
        pcap_rotate_seconds=args.get("pcap_rotate_seconds"),
        verbose=args.get("verbose", False),
        stop_event=stop_event
    )

def _adapter_campaign(args: Dict[str, Any], stop_event: threading.Event) -> None:
    run_campaign(
        campaign_file=args.get("campaign_file"),
        dry_run=args.get("dry_run", False),
        stop_event=stop_event
    )

JOB_ADAPTERS = {
    "monitor": _adapter_monitor,
    "profile": _adapter_profile,
    "campaign": _adapter_campaign,
    # Add others as needed
}

class Job:
    def __init__(self, job_id: str, job_type: str, args: Dict[str, Any]):
        self.id = job_id
        self.type = job_type
        self.args = args
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.status = "pending"
        self.start_time = 0.0
        self.end_time: Optional[float] = None
        self.error: Optional[str] = None

    def run(self) -> None:
        self.status = "running"
        self.start_time = time.time()
        try:
            target = JOB_ADAPTERS.get(self.type)
            if not target:
                raise ValueError(f"Unknown job type: {self.type}")
            target(self.args, self.stop_event)
            self.status = "completed"
        except Exception as e:
            self.status = "failed"
            self.error = str(e)
            print(f"Job {self.id} failed: {e}")
        finally:
            self.end_time = time.time()

    def stop(self) -> None:
        self.stop_event.set()

class JobManager:
    def __init__(self) -> None:
        self.jobs: Dict[str, Job] = {}
        self.lock = threading.Lock()

    def start_job(self, job_type: str, args: Dict[str, Any]) -> str:
        if job_type not in JOB_ADAPTERS:
             raise ValueError(f"Invalid job type: {job_type}")
             
        job_id = str(uuid.uuid4())[:8]
        job = Job(job_id, job_type, args)
        
        with self.lock:
            self.jobs[job_id] = job
        
        t = threading.Thread(target=job.run, daemon=True)
        job.thread = t
        t.start()
        
        return job_id

    def stop_job(self, job_id: str) -> bool:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return False
            job.stop()
            job.status = "stopped" # Optimistic update
            return True

    def get_job(self, job_id: str) -> Optional[JobStatus]:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return None
            return JobStatus(
                job_id=job.id,
                type=job.type,
                status=job.status,
                start_time=job.start_time,
                end_time=job.end_time,
                error=job.error,
                args=job.args
            )

    def list_jobs(self) -> list[JobStatus]:
        with self.lock:
            return [
                JobStatus(
                    job_id=job.id,
                    type=job.type,
                    status=job.status,
                    start_time=job.start_time,
                    end_time=job.end_time,
                    error=job.error,
                    args=job.args
                )
                for job in self.jobs.values()
            ]

# Global instance
manager = JobManager()
