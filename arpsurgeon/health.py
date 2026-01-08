from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from scapy.all import ICMP, IP, conf, sr1  # type: ignore

from arpsurgeon.arp import ArpTarget, resolve_mac


@dataclass
class HealthResult:
    ip: str
    mac: Optional[str]
    arp_ok: bool
    icmp_ok: Optional[bool]
    rtt_ms: Optional[float]


def ping_host(ip: str, iface: Optional[str], timeout: float = 1.0) -> Optional[float]:
    if iface:
        conf.iface = iface
    pkt = IP(dst=ip) / ICMP()
    start = time.monotonic()
    reply = sr1(pkt, timeout=timeout, verbose=False)
    if reply is None:
        return None
    rtt = (time.monotonic() - start) * 1000
    return rtt


def check_targets(
    ips: list[str],
    iface: Optional[str],
    ping: bool,
    timeout: float,
) -> list[HealthResult]:
    results = []
    for ip in ips:
        mac = resolve_mac(ip, iface)
        arp_ok = mac is not None
        icmp_ok = None
        rtt = None
        if ping:
            rtt = ping_host(ip, iface, timeout=timeout)
            icmp_ok = rtt is not None
        results.append(
            HealthResult(ip=ip, mac=mac, arp_ok=arp_ok, icmp_ok=icmp_ok, rtt_ms=rtt)
        )
    return results


def to_targets(results: list[HealthResult]) -> list[ArpTarget]:
    targets = []
    for result in results:
        if result.mac:
            targets.append(ArpTarget(ip=result.ip, mac=result.mac))
    return targets
