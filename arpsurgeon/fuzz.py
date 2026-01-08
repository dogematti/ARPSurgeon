from __future__ import annotations

import random
import time
from threading import Event
from typing import Optional

from scapy.all import ARP, Ether, IP, Raw, conf, sendp  # type: ignore

def _random_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))

def _random_ip() -> str:
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def fuzz_l2(
    iface: Optional[str],
    mode: str = "random",
    rate: int = 10,
    duration: Optional[int] = None,
    dry_run: bool = False,
    stop_event: Optional[Event] = None,
) -> None:
    if iface:
        conf.iface = iface

    print(f"[*] Fuzzing L2 on {conf.iface} mode={mode} rate={rate}/s")
    if dry_run:
        print("[*] Dry-run mode: no packets will be sent.")

    start_time = time.time()
    count = 0

    while True:
        if stop_event and stop_event.is_set():
            break
        if duration and (time.time() - start_time) > duration:
            break

        pkt = None
        strategy = mode
        if mode == "random":
            strategy = random.choice(["arp_opcode", "ether_type", "mac_flood", "malformed", "bogus_ip"])

        if strategy == "arp_opcode":
            # Invalid ARP Opcode
            # Valid are 1 (req) and 2 (rep). Try 0, 3, 255, 65535
            op = random.choice([0, 3, 4, 8, 255, 65535])
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=op, pdst=_random_ip())

        elif strategy == "ether_type":
            # Random EtherType
            etype = random.randint(0, 65535)
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff", type=etype) / Raw(b"FUZZ" * 10)

        elif strategy == "mac_flood":
            # Random Source MAC (CAM Table overflow attempt)
            pkt = Ether(src=_random_mac(), dst="ff:ff:ff:ff:ff:ff") / IP(src=_random_ip(), dst="255.255.255.255") / Raw(b"FLOOD")

        elif strategy == "malformed":
            # Truncated or weird structure
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / Raw(b"\x00" * random.randint(1, 50))
            
        elif strategy == "bogus_ip":
            # IP packet with weird header values
            pkt = Ether() / IP(src=_random_ip(), dst=_random_ip(), version=random.choice([0, 5, 15]), ihl=random.choice([0, 1, 15])) / Raw(b"BOGUS")

        if pkt:
            if not dry_run:
                sendp(pkt, verbose=0)
            count += 1
        
        # Rate limiting
        time.sleep(1.0 / rate)

    print(f"[*] Fuzzing complete. Sent {count} packets.")
