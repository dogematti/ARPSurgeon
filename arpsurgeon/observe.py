from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Event
from typing import Deque, Dict, Optional, Tuple

from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, Ether, IP, UDP, conf, sniff  # type: ignore

from arpsurgeon.fingerprint import guess_os, guess_os_dhcp
from arpsurgeon.notify import send_notification
from arpsurgeon.oui import lookup_vendor, load_oui_map
from arpsurgeon.session_log import JsonlLogger, PcapLogger
from arpsurgeon.storage import Database


@dataclass
class Observation:
    requester: str
    target: str
    interval: float
    timestamp: float


class ArpObserver:
    def __init__(self) -> None:
        self._last_seen: Dict[Tuple[str, str], float] = {}
        self._intervals: Dict[Tuple[str, str], Deque[float]] = defaultdict(lambda: deque(maxlen=5))

    def ingest(self, requester: str, target: str, timestamp: float) -> Optional[Observation]:
        key = (requester, target)
        last = self._last_seen.get(key)
        self._last_seen[key] = timestamp
        if last is None:
            return None
        interval = timestamp - last
        if interval <= 0:
            return None
        self._intervals[key].append(interval)
        return Observation(requester=requester, target=target, interval=interval, timestamp=timestamp)

    def predict_next(self, requester: str, target: str) -> Optional[float]:
        key = (requester, target)
        if key not in self._intervals or not self._intervals[key]:
            return None
        avg = sum(self._intervals[key]) / len(self._intervals[key])
        last = self._last_seen.get(key)
        if last is None:
            return None
        return last + avg


def observe(
    iface: Optional[str],
    duration: Optional[int],
    json_path: Optional[str],
    jsonl_path: Optional[str],
    pcap_path: Optional[str],
    pcap_filter: str,
    pcap_rotate_mb: Optional[int],
    pcap_rotate_seconds: Optional[int],
    verbose: bool,
    stop_event: Optional[Event] = None,
) -> None:
    if iface:
        conf.iface = iface
    observer = ArpObserver()
    events = []
    jsonl_logger = JsonlLogger(jsonl_path)
    max_bytes = pcap_rotate_mb * 1024 * 1024 if pcap_rotate_mb else None
    pcap_logger = PcapLogger(pcap_path, max_bytes=max_bytes, max_seconds=pcap_rotate_seconds)

    def handler(pkt) -> None:
        pcap_logger.write(pkt)
        if not pkt.haslayer(ARP):
            return
        arp = pkt.getlayer(ARP)
        if arp.op != 1:
            return
        timestamp = time.time()
        obs = observer.ingest(arp.psrc, arp.pdst, timestamp)
        if not obs:
            return
        next_time = observer.predict_next(obs.requester, obs.target)
        if verbose:
            next_str = time.strftime("%H:%M:%S", time.localtime(next_time)) if next_time else "n/a"
            print(
                f"refresh {obs.requester} -> {obs.target} interval={obs.interval:.2f}s "
                f"next≈{next_str}"
            )
        payload = {
            "type": "refresh",
            "requester": obs.requester,
            "target": obs.target,
            "interval": obs.interval,
            "timestamp": obs.timestamp,
            "next_prediction": next_time,
        }
        if json_path:
            events.append(payload)
        jsonl_logger.log(payload)

    sniff(
        filter=pcap_filter,
        prn=handler,
        store=False,
        timeout=duration,
        stop_filter=lambda x: stop_event.is_set() if stop_event else False
    )

    if json_path:
        with open(json_path, "w", encoding="ascii") as handle:
            json.dump({"events": events}, handle, indent=2)
    jsonl_logger.close()
    pcap_logger.close()


def profile(
    iface: Optional[str],
    duration: Optional[int],
    oui_file: Optional[str],
    json_path: Optional[str],
    jsonl_path: Optional[str],
    pcap_path: Optional[str],
    pcap_filter: str,
    pcap_rotate_mb: Optional[int],
    pcap_rotate_seconds: Optional[int],
    verbose: bool,
    stop_event: Optional[Event] = None,
) -> None:
    if iface:
        conf.iface = iface
    observer = ArpObserver()
    seen: Dict[str, dict] = {}
    mac_to_ip: Dict[str, str] = {}
    jsonl_logger = JsonlLogger(jsonl_path)
    max_bytes = pcap_rotate_mb * 1024 * 1024 if pcap_rotate_mb else None
    pcap_logger = PcapLogger(pcap_path, max_bytes=max_bytes, max_seconds=pcap_rotate_seconds)
    oui_map = load_oui_map(oui_file)
    db = Database()

    def handler(pkt) -> None:
        pcap_logger.write(pkt)
        timestamp = time.time()

        # Passive Service Discovery (mDNS/LLMNR/NBNS)
        if pkt.haslayer(UDP) and pkt.haslayer(DNS):
            udp = pkt.getlayer(UDP)
            if udp.sport in (5353, 5355, 137) or udp.dport in (5353, 5355, 137):
                dns = pkt.getlayer(DNS)
                # Parse Answers (an) and Additional Records (ar) for A records (Type 1)
                # mDNS/LLMNR announcements put the mapping in Answers.
                for section in (dns.an, dns.ar):
                    curr = section
                    while curr:
                        if curr.type == 1:  # A Record
                            try:
                                rdata_ip = curr.rdata
                                rrname = curr.rrname.decode("utf-8", errors="ignore").rstrip(".")
                                
                                # Filter out noise
                                if rdata_ip and rrname and len(rrname) > 1:
                                    # Update host entry
                                    entry = seen.get(rdata_ip)
                                    if entry:
                                        # Clean up common suffixes
                                        if rrname.endswith(".local"):
                                            rrname = rrname[:-6]
                                        entry["hostname"] = rrname
                                        db.upsert_host(entry)
                            except (AttributeError, UnicodeDecodeError):
                                pass
                        curr = curr.payload if hasattr(curr, "payload") and isinstance(curr.payload, type(curr)) else None

        if pkt.haslayer(DHCP):
            # Extract Option 55 (Parameter Request List)
            options = pkt[DHCP].options
            req_list = None
            # Extract Hostname (Option 12) as well!
            dhcp_hostname = None
            
            for opt in options:
                if isinstance(opt, tuple):
                    if opt[0] == 'param_req_list':
                        req_list = opt[1]
                    elif opt[0] == 'hostname':
                        try:
                            dhcp_hostname = opt[1].decode("utf-8", errors="ignore")
                        except (AttributeError, UnicodeDecodeError):
                            pass
            
            if req_list:
                # Convert bytes to list of ints if needed
                if isinstance(req_list, bytes):
                    req_list = list(req_list)
                
                os_guess = guess_os_dhcp(req_list)
                if os_guess:
                    # Try to map MAC to IP to update the host entry
                    # DHCP packet might be from 0.0.0.0, so rely on MAC
                    src_mac = pkt.getlayer(BOOTP).chaddr if pkt.haslayer(BOOTP) else None
                    # Convert raw bytes chaddr to string MAC if needed, or just use Ether src
                    if not src_mac and pkt.haslayer(Ether):
                         src_mac = pkt.getlayer(Ether).src
                    
                    # If BOOTP chaddr is bytes, format it? Scapy usually parses it.
                    # Simplest is Ether src.
                    if not src_mac and pkt.haslayer(Ether):
                        src_mac = pkt.getlayer(Ether).src
                        
                    if src_mac:
                        # Normalize MAC if needed? Scapy strings are usually colon-sep.
                        # Check mac_to_ip cache
                        target_ip = mac_to_ip.get(src_mac)
                        if target_ip and target_ip in seen:
                            seen[target_ip]["os"] = f"{os_guess} (DHCP)"
                            if dhcp_hostname:
                                seen[target_ip]["hostname"] = dhcp_hostname
                            db.upsert_host(seen[target_ip])

        if pkt.haslayer(IP):
            ip = pkt.getlayer(IP)
            if ip.src:
                if pkt.haslayer(Ether):
                    mac_to_ip[pkt.getlayer(Ether).src] = ip.src
                    
                entry = seen.get(ip.src)
                if not entry:
                    # Initialize entry if seen via IP but not ARP yet
                    entry = seen.setdefault(
                        ip.src,
                        {
                            "ip": ip.src,
                            "mac": "unknown",
                            "first_seen": timestamp,
                            "last_seen": timestamp,
                            "count": 0,
                            "os": "unknown",
                        },
                    )
                
                # Update OS guess if unknown or refine generic TTL guess
                # Don't overwrite DHCP guess (which is high confidence)
                current_os = entry.get("os", "unknown")
                if "DHCP" not in current_os:
                    ttl_guess = guess_os(ip.ttl)
                    if current_os in ("unknown", "Unknown") and ttl_guess != "Unknown":
                         entry["os"] = ttl_guess
                    # Could refine logic here (e.g. if TTL guess differs from previous non-DHCP guess?)
                
                entry["last_seen"] = timestamp
                db.upsert_host(entry)

        if pkt.haslayer(ARP):
            arp = pkt.getlayer(ARP)
            if arp.psrc and arp.hwsrc:
                mac_to_ip[arp.hwsrc] = arp.psrc
                entry = seen.setdefault(
                    arp.psrc,
                    {
                        "ip": arp.psrc,
                        "mac": arp.hwsrc,
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                        "count": 0,
                        "os": "unknown",
                    },
                )
                entry["last_seen"] = timestamp
                entry["mac"] = arp.hwsrc
                entry["count"] += 1
                vendor = lookup_vendor(arp.hwsrc, oui_map)
                if vendor:
                    entry["vendor"] = vendor
                db.upsert_host(entry)
            if arp.op == 1:
                obs = observer.ingest(arp.psrc, arp.pdst, timestamp)
                if obs:
                    db.update_refresh_stat(obs.requester, obs.target, obs.interval)
                    jsonl_logger.log(
                        {
                            "type": "refresh",
                            "requester": obs.requester,
                            "target": obs.target,
                            "interval": obs.interval,
                            "timestamp": obs.timestamp,
                        }
                    )

    sniff(
        filter=pcap_filter,
        prn=handler,
        store=False,
        timeout=duration,
        stop_filter=lambda x: stop_event.is_set() if stop_event else False
    )

    refresh_stats = []
    for (requester, target), intervals in observer._intervals.items():
        if not intervals:
            continue
        refresh_stats.append(
            {
                "requester": requester,
                "target": target,
                "avg_interval": sum(intervals) / len(intervals),
                "samples": len(intervals),
            }
        )

    if verbose:
        print("passive arp table")
        for entry in sorted(seen.values(), key=lambda item: item["ip"]):
            vendor = entry.get("vendor", "unknown")
            print(
                f"{entry['ip']:>15} {entry['mac']:>17} "
                f"seen={entry['count']:>4} vendor={vendor}"
            )
        print("refresh statistics")
        for stat in refresh_stats:
            print(
                f"{stat['requester']} -> {stat['target']} "
                f"avg={stat['avg_interval']:.2f}s samples={stat['samples']}"
            )

    report = {"hosts": list(seen.values()), "refresh_stats": refresh_stats}
    if json_path:
        with open(json_path, "w", encoding="ascii") as handle:
            json.dump(report, handle, indent=2)
    jsonl_logger.log({"type": "profile_summary", "hosts": len(seen), "stats": len(refresh_stats)})
    jsonl_logger.close()
    pcap_logger.close()


def monitor(
    iface: Optional[str],
    duration: Optional[int],
    jsonl_path: Optional[str],
    pcap_path: Optional[str],
    pcap_filter: str,
    storm_threshold: int,
    storm_window: int,
    pcap_rotate_mb: Optional[int],
    pcap_rotate_seconds: Optional[int],
    verbose: bool,
    stop_event: Optional[Event] = None,
) -> None:
    if iface:
        conf.iface = iface
    jsonl_logger = JsonlLogger(jsonl_path)
    max_bytes = pcap_rotate_mb * 1024 * 1024 if pcap_rotate_mb else None
    pcap_logger = PcapLogger(pcap_path, max_bytes=max_bytes, max_seconds=pcap_rotate_seconds)
    db = Database()

    ip_to_mac: Dict[str, str] = {}
    timestamps: Deque[float] = deque()

    def handler(pkt) -> None:
        pcap_logger.write(pkt)
        if not pkt.haslayer(ARP):
            return
        arp = pkt.getlayer(ARP)
        now = time.time()

        timestamps.append(now)
        while timestamps and now - timestamps[0] > storm_window:
            timestamps.popleft()
        if len(timestamps) >= storm_threshold:
            payload = {"type": "storm", "count": len(timestamps), "window": storm_window, "ts": now}
            if verbose:
                print(f"alert: arp storm count={len(timestamps)} window={storm_window}s")
            jsonl_logger.log(payload)
            db.log_event("storm", payload)
            send_notification("storm", payload)

        if arp.op == 2 and arp.psrc and arp.hwsrc:
            current = ip_to_mac.get(arp.psrc)
            if current and current.lower() != arp.hwsrc.lower():
                payload = {
                    "type": "conflict",
                    "ip": arp.psrc,
                    "old_mac": current,
                    "new_mac": arp.hwsrc,
                    "ts": now,
                }
                if verbose:
                    print(
                        f"alert: arp conflict ip={arp.psrc} old={current} new={arp.hwsrc}"
                    )
                jsonl_logger.log(payload)
                db.log_event("conflict", payload)
                send_notification("conflict", payload)
            ip_to_mac[arp.psrc] = arp.hwsrc

        if arp.psrc == arp.pdst and arp.psrc:
            payload = {"type": "gratuitous", "ip": arp.psrc, "mac": arp.hwsrc, "ts": now}
            if verbose:
                print(f"alert: gratuitous arp ip={arp.psrc} mac={arp.hwsrc}")
            jsonl_logger.log(payload)
            db.log_event("gratuitous", payload)
            send_notification("gratuitous", payload)

    sniff(
        filter=pcap_filter,
        prn=handler,
        store=False,
        timeout=duration,
        stop_filter=lambda x: stop_event.is_set() if stop_event else False
    )
    jsonl_logger.close()
    pcap_logger.close()
