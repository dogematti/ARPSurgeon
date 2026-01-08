from __future__ import annotations

from typing import Optional

from scapy.all import ARP, Ether, conf, srp  # type: ignore

from arpsurgeon.arp import ArpTarget
from arpsurgeon.oui import lookup_vendor, load_oui_map


def arp_scan(
    cidr: str,
    iface: Optional[str],
    timeout: float,
    retry: int,
    oui_file: Optional[str],
    dry_run: bool,
) -> list[dict]:
    if iface:
        conf.iface = iface
    if dry_run:
        return []
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(pkt, timeout=timeout, retry=retry, verbose=False)
    oui_map = load_oui_map(oui_file)
    results = []
    for _, reply in answered:
        vendor = lookup_vendor(reply.hwsrc, oui_map)
        results.append(
            {
                "ip": reply.psrc,
                "mac": reply.hwsrc,
                "vendor": vendor,
            }
        )
    return results


def to_targets(scan_results: list[dict]) -> list[ArpTarget]:
    targets = []
    for result in scan_results:
        if result.get("ip") and result.get("mac"):
            targets.append(ArpTarget(ip=result["ip"], mac=result["mac"]))
    return targets
