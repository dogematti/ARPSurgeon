from __future__ import annotations

from typing import Optional

from scapy.all import ARP, Ether, conf, send, srp  # type: ignore

from arpsurgeon.arp import resolve_mac


def snapshot_ips(
    ips: list[str],
    iface: Optional[str],
    timeout: float,
    dry_run: bool,
) -> list[dict]:
    if iface:
        conf.iface = iface
    if dry_run:
        return []
    entries = []
    for ip in ips:
        mac = resolve_mac(ip, iface, timeout=timeout)
        if mac:
            entries.append({"ip": ip, "mac": mac})
    return entries


def snapshot_cidr(
    cidr: str,
    iface: Optional[str],
    timeout: float,
    retry: int,
    dry_run: bool,
) -> list[dict]:
    if iface:
        conf.iface = iface
    if dry_run:
        return []
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(pkt, timeout=timeout, retry=retry, verbose=False)
    entries = []
    for _, reply in answered:
        entries.append({"ip": reply.psrc, "mac": reply.hwsrc})
    return entries


def restore_snapshot(
    entries: list[dict],
    iface: Optional[str],
    count: int,
    dry_run: bool,
) -> None:
    if iface:
        conf.iface = iface
    if dry_run:
        return
    for entry in entries:
        ip = entry.get("ip")
        mac = entry.get("mac")
        if not ip or not mac:
            continue
        pkt = ARP(op=2, psrc=ip, pdst=ip, hwsrc=mac, hwdst="ff:ff:ff:ff:ff:ff")
        send(pkt, count=count, verbose=False)
