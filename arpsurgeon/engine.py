from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any, Dict, Optional

from arpsurgeon.campaign import run_campaign
from arpsurgeon.log import get_logger
from arpsurgeon.models import JobStatus
from arpsurgeon.observe import monitor, observe, profile

logger = get_logger("engine")

# ---------------------------------------------------------------------------
# Adapter helpers
# ---------------------------------------------------------------------------

def _resolve_targets(victim_ips: list[str], iface: str | None) -> list:
    from arpsurgeon.arp import ArpTarget, resolve_mac
    targets = []
    for ip in victim_ips:
        mac = resolve_mac(ip, iface)
        if not mac:
            raise ValueError(f"Could not resolve MAC for {ip}")
        targets.append(ArpTarget(ip=ip, mac=mac))
    return targets


def _resolve_gateway_target(gateway_ip: str, iface: str | None):
    from arpsurgeon.arp import ArpTarget, resolve_mac
    mac = resolve_mac(gateway_ip, iface)
    if not mac:
        raise ValueError(f"Could not resolve MAC for gateway {gateway_ip}")
    return ArpTarget(ip=gateway_ip, mac=mac)


# ---------------------------------------------------------------------------
# Existing adapters
# ---------------------------------------------------------------------------

def _adapter_monitor(args: Dict[str, Any], stop_event: threading.Event) -> None:
    monitor(
        iface=args.get("iface"),
        duration=args.get("duration"),
        jsonl_path=args.get("jsonl"),
        pcap_path=args.get("pcap"),
        pcap_filter=args.get("pcap_filter", ""),
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

# ---------------------------------------------------------------------------
# New adapters
# ---------------------------------------------------------------------------

def _adapter_discover(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.discover import arp_scan
    from arpsurgeon.storage import Database
    results = arp_scan(
        cidr=args["cidr"],
        iface=args.get("iface"),
        timeout=args.get("timeout", 2.0),
        retry=args.get("retry", 1),
        oui_file=args.get("oui_file"),
        dry_run=args.get("dry_run", False),
    )
    db = Database()
    for host in results:
        db.upsert_host(host)


def _adapter_observe(args: Dict[str, Any], stop_event: threading.Event) -> None:
    observe(
        iface=args.get("iface"),
        duration=args.get("duration"),
        json_path=args.get("json"),
        jsonl_path=args.get("jsonl"),
        pcap_path=args.get("pcap"),
        pcap_filter=args.get("pcap_filter", "arp"),
        pcap_rotate_mb=args.get("pcap_rotate_mb"),
        pcap_rotate_seconds=args.get("pcap_rotate_seconds"),
        verbose=args.get("verbose", False),
        stop_event=stop_event,
    )


def _adapter_poison(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.arp import poison, restore
    from arpsurgeon.utils import enable_ip_forwarding, disable_ip_forwarding

    iface = args.get("iface")
    victims = _resolve_targets(args["victim"], iface)
    gateway = _resolve_gateway_target(args["gateway"], iface)
    forward = args.get("forward", False)
    restore_after = args.get("restore", True)

    if forward:
        enable_ip_forwarding()
    try:
        poison(
            victims, gateway, iface,
            interval=args.get("interval", 2.0),
            duration=args.get("duration"),
            stagger=args.get("stagger", 0.0),
            jitter=args.get("jitter", 0.0),
            dry_run=args.get("dry_run", False),
            should_stop=stop_event.is_set,
        )
    finally:
        if restore_after:
            restore(victims, gateway, iface, dry_run=args.get("dry_run", False))
        if forward:
            disable_ip_forwarding()


def _adapter_restore(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.arp import restore

    iface = args.get("iface")
    victims = _resolve_targets(args["victim"], iface)
    gateway = _resolve_gateway_target(args["gateway"], iface)
    restore(victims, gateway, iface, dry_run=args.get("dry_run", False))


def _adapter_mitm(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.arp import poison, restore
    from arpsurgeon.relay import relay
    from arpsurgeon.dns_spoof import dns_spoof
    from arpsurgeon.utils import enable_ip_forwarding, disable_ip_forwarding

    iface = args.get("iface")
    victims = _resolve_targets(args["victim"], iface)
    gateway = _resolve_gateway_target(args["gateway"], iface)
    dry_run = args.get("dry_run", False)
    forward = args.get("forward", False)
    restore_after = args.get("restore", True)

    if forward:
        enable_ip_forwarding()

    threads: list[threading.Thread] = []

    def run_poison():
        poison(
            victims, gateway, iface,
            interval=args.get("interval", 2.0),
            duration=None,
            stagger=args.get("stagger", 0.0),
            jitter=args.get("jitter", 0.0),
            dry_run=dry_run,
            should_stop=stop_event.is_set,
        )

    threads.append(threading.Thread(target=run_poison, daemon=True))

    if not args.get("no_relay", False):
        def run_relay():
            relay(
                victims, gateway, iface,
                duration=None,
                pcap_path=args.get("relay_pcap"),
                jsonl_path=args.get("relay_jsonl"),
                pcap_filter=args.get("pcap_filter"),
                max_rate=args.get("relay_rate"),
                dry_run=dry_run,
                stop_event=stop_event,
                pcap_rotate_mb=args.get("pcap_rotate_mb"),
                pcap_rotate_seconds=args.get("pcap_rotate_seconds"),
            )
        threads.append(threading.Thread(target=run_relay, daemon=True))

    if not args.get("no_dns", False):
        def run_dns():
            dns_spoof(
                iface=iface,
                duration=None,
                hosts_file=args.get("dns_hosts_file"),
                default_ip=args.get("dns_default_ip"),
                targets=args.get("dns_target") or [],
                jsonl_path=args.get("dns_jsonl"),
                pcap_path=args.get("dns_pcap"),
                pcap_filter="udp port 53",
                ttl=args.get("dns_ttl", 60),
                max_rate=args.get("dns_rate"),
                dry_run=dry_run,
                stop_event=stop_event,
                pcap_rotate_mb=args.get("pcap_rotate_mb"),
                pcap_rotate_seconds=args.get("pcap_rotate_seconds"),
            )
        threads.append(threading.Thread(target=run_dns, daemon=True))

    for t in threads:
        t.start()

    try:
        duration = args.get("duration")
        if duration:
            deadline = time.monotonic() + duration
            while not stop_event.is_set() and time.monotonic() < deadline:
                time.sleep(0.5)
            stop_event.set()
        else:
            while not stop_event.is_set():
                time.sleep(0.5)
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=2)
        if restore_after:
            restore(victims, gateway, iface, dry_run=dry_run)
        if forward:
            disable_ip_forwarding()


def _adapter_sever(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.sever import sever_connection
    sever_connection(
        target_ip=args["target"],
        target_port=args.get("port"),
        iface=args.get("iface"),
        duration=args.get("duration"),
        dry_run=args.get("dry_run", False),
        stop_event=stop_event,
    )


def _adapter_fuzz(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.fuzz import fuzz_l2
    fuzz_l2(
        iface=args.get("iface"),
        mode=args.get("mode", "random"),
        rate=args.get("rate", 10),
        duration=args.get("duration"),
        dry_run=args.get("dry_run", False),
        stop_event=stop_event,
    )


def _adapter_dns_spoof(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.dns_spoof import dns_spoof
    dns_spoof(
        iface=args.get("iface"),
        duration=args.get("duration"),
        hosts_file=args.get("hosts_file"),
        default_ip=args.get("default_ip"),
        targets=args.get("target") or [],
        jsonl_path=args.get("jsonl"),
        pcap_path=args.get("pcap"),
        pcap_filter=args.get("pcap_filter", "udp port 53"),
        ttl=args.get("ttl", 60),
        max_rate=args.get("rate"),
        dry_run=args.get("dry_run", False),
        stop_event=stop_event,
        pcap_rotate_mb=args.get("pcap_rotate_mb"),
        pcap_rotate_seconds=args.get("pcap_rotate_seconds"),
    )


def _adapter_check(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.health import check_targets
    from arpsurgeon.storage import Database
    results = check_targets(
        targets=args["victim"],
        iface=args.get("iface"),
        timeout=args.get("timeout", 1.0),
        do_ping=args.get("ping", False),
    )
    db = Database()
    db.log_event("health_check", {
        "results": [
            {"ip": r.ip, "mac": r.mac, "arp_ok": r.arp_ok,
             "icmp_ok": r.icmp_ok, "rtt_ms": r.rtt_ms}
            for r in results
        ]
    })


def _adapter_snapshot(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.arp_cache import snapshot_cidr, snapshot_ips
    from pathlib import Path

    iface = args.get("iface")
    dry_run = args.get("dry_run", False)

    if args.get("cidr"):
        entries = snapshot_cidr(
            cidr=args["cidr"], iface=iface,
            timeout=args.get("timeout", 2.0),
            retry=args.get("retry", 1),
            dry_run=dry_run,
        )
    else:
        entries = snapshot_ips(
            ips=args.get("victim", []), iface=iface,
            timeout=args.get("timeout", 2.0),
            dry_run=dry_run,
        )
    output = args.get("output", "snapshot.json")
    Path(output).write_text(json.dumps(entries, indent=2))


def _adapter_restore_snapshot(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.arp_cache import restore_snapshot
    from pathlib import Path

    entries = json.loads(Path(args["input"]).read_text())
    restore_snapshot(
        entries=entries,
        iface=args.get("iface"),
        count=args.get("count", 3),
        dry_run=args.get("dry_run", False),
    )


def _adapter_relay(args: Dict[str, Any], stop_event: threading.Event) -> None:
    from arpsurgeon.relay import relay

    iface = args.get("iface")
    victims = _resolve_targets(args["victim"], iface)
    gateway = _resolve_gateway_target(args["gateway"], iface)
    relay(
        victims, gateway, iface,
        duration=args.get("duration"),
        pcap_path=args.get("pcap"),
        jsonl_path=args.get("jsonl"),
        pcap_filter=args.get("pcap_filter"),
        max_rate=args.get("rate"),
        dry_run=args.get("dry_run", False),
        stop_event=stop_event,
        pcap_rotate_mb=args.get("pcap_rotate_mb"),
        pcap_rotate_seconds=args.get("pcap_rotate_seconds"),
    )


# ---------------------------------------------------------------------------
# Adapter registry
# ---------------------------------------------------------------------------

JOB_ADAPTERS = {
    "monitor": _adapter_monitor,
    "profile": _adapter_profile,
    "campaign": _adapter_campaign,
    "discover": _adapter_discover,
    "observe": _adapter_observe,
    "poison": _adapter_poison,
    "restore": _adapter_restore,
    "mitm": _adapter_mitm,
    "sever": _adapter_sever,
    "fuzz": _adapter_fuzz,
    "dns-spoof": _adapter_dns_spoof,
    "check": _adapter_check,
    "snapshot": _adapter_snapshot,
    "restore-snapshot": _adapter_restore_snapshot,
    "relay": _adapter_relay,
}


# ---------------------------------------------------------------------------
# Job & JobManager
# ---------------------------------------------------------------------------

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

    @property
    def duration(self) -> Optional[float]:
        if self.start_time == 0.0:
            return None
        end = self.end_time if self.end_time else time.time()
        return end - self.start_time

    def run(self) -> None:
        self.status = "running"
        self.start_time = time.time()
        logger.info("Job %s (%s) started", self.id, self.type)
        try:
            target = JOB_ADAPTERS.get(self.type)
            if not target:
                raise ValueError(f"Unknown job type: {self.type}")
            target(self.args, self.stop_event)
            self.status = "completed"
            logger.info("Job %s (%s) completed (%.1fs)", self.id, self.type,
                        self.duration or 0)
        except Exception as e:
            self.status = "failed"
            self.error = str(e)
            logger.error("Job %s (%s) failed: %s", self.id, self.type, e)
        finally:
            self.end_time = time.time()

    def stop(self) -> None:
        self.stop_event.set()


# Default retention: keep finished jobs for 1 hour
_JOB_RETENTION_SECONDS = 3600


class JobManager:
    def __init__(self) -> None:
        self.jobs: Dict[str, Job] = {}
        self.lock = threading.Lock()

    def _cleanup_old_jobs(self) -> None:
        """Remove completed/failed/stopped jobs older than retention period."""
        cutoff = time.time() - _JOB_RETENTION_SECONDS
        to_remove = [
            jid for jid, job in self.jobs.items()
            if job.status in ("completed", "failed", "stopped")
            and job.end_time is not None
            and job.end_time < cutoff
        ]
        for jid in to_remove:
            del self.jobs[jid]

    def start_job(self, job_type: str, args: Dict[str, Any]) -> str:
        if job_type not in JOB_ADAPTERS:
             raise ValueError(f"Invalid job type: {job_type}")

        job_id = str(uuid.uuid4())[:8]
        job = Job(job_id, job_type, args)

        with self.lock:
            self._cleanup_old_jobs()
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
            job.status = "stopped"
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
            self._cleanup_old_jobs()
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
