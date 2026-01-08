from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from threading import Event, Thread
from typing import Optional

from scapy.all import conf  # type: ignore

import uvicorn

from arpsurgeon.arp import ArpTarget, poison, resolve_mac, restore, verify_targets
from arpsurgeon.arp_cache import restore_snapshot, snapshot_cidr, snapshot_ips
from arpsurgeon.campaign import run_campaign
from arpsurgeon.config import apply_config, load_config
from arpsurgeon.dashboard import run_dashboard
from arpsurgeon.discover import arp_scan
from arpsurgeon.dns_spoof import dns_spoof
from arpsurgeon.fuzz import fuzz_l2
from arpsurgeon.health import check_targets
from arpsurgeon.observe import monitor, observe, profile
from arpsurgeon.relay import relay
from arpsurgeon.report import export_report
from arpsurgeon.session_log import JsonlLogger
from arpsurgeon.sever import sever_connection
from arpsurgeon.utils import (
    default_gateway_ip,
    disable_ip_forwarding,
    enable_ip_forwarding,
    list_interfaces,
    require_root,
    select_iface,
)


def _resolve_target(ip: str, iface: str | None, label: str) -> ArpTarget:
    mac = resolve_mac(ip, iface)
    if not mac:
        raise SystemExit(f"failed to resolve {label} MAC for {ip}")
    return ArpTarget(ip=ip, mac=mac)

def _load_victims(args: argparse.Namespace) -> list[str]:
    victims = list(args.victim or [])
    if args.victims_file:
        path = Path(args.victims_file)
        if not path.exists():
            raise SystemExit(f"victims file not found: {path}")
        for line in path.read_text(encoding="ascii").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            victims.append(line)
    if args.victims_json:
        victims.extend(_load_victims_json(args.victims_json))
    if not victims:
        raise SystemExit("at least one --victim or --victims-file is required")
    if args.victims_limit:
        victims = victims[: args.victims_limit]
    return victims


def _load_victims_json(path: str) -> list[str]:
    data = json.loads(Path(path).read_text(encoding="ascii"))
    for key in ("results", "hosts", "entries"):
        if key in data and isinstance(data[key], list):
            return [item.get("ip") for item in data[key] if item.get("ip")]
    return []


def _select_iface(args: argparse.Namespace) -> Optional[str]:
    iface = select_iface(args.iface)
    if iface:
        conf.iface = iface
    return iface


def _confirm(prompt: str, assume_yes: bool) -> None:
    if assume_yes:
        return
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        raise SystemExit("aborted")


def _resolve_gateway(args: argparse.Namespace, iface: Optional[str]) -> str:
    if args.gateway:
        return args.gateway
    gateway = default_gateway_ip()
    if not gateway:
        raise SystemExit("gateway not provided and default gateway not found")
    _confirm(f"use default gateway {gateway}?", args.yes)
    return gateway


def _sleep_until(start_at: Optional[str], start_in: Optional[float]) -> None:
    if start_in is not None:
        if start_in > 0:
            time.sleep(start_in)
        return
    if not start_at:
        return
    try:
        target = datetime.fromisoformat(start_at)
    except ValueError as exc:
        raise SystemExit(f"invalid --start-at value: {start_at}") from exc
    if target.tzinfo is None:
        local_tz = datetime.now().astimezone().tzinfo
        target = target.replace(tzinfo=local_tz)
    else:
        target = target.astimezone()
    delay = (target - datetime.now(tz=target.tzinfo)).total_seconds()
    if delay > 0:
        time.sleep(delay)


def _build_host_filter(hosts: list[str]) -> Optional[str]:
    if not hosts:
        return None
    return " or ".join([f"host {host}" for host in hosts])


def _select_pcap_filter(
    args: argparse.Namespace,
    default_filter: str,
    hosts: Optional[list[str]] = None,
) -> str:
    if getattr(args, "pcap_filter", None):
        return args.pcap_filter
    preset = getattr(args, "pcap_preset", None)
    if not preset:
        return default_filter
    if preset == "arp":
        return "arp"
    if preset == "dns":
        return "udp port 53"
    if preset == "ip":
        return "ip"
    if preset in {"arp-targets", "ip-targets"}:
        host_filter = _build_host_filter(hosts or [])
        if not host_filter:
            return default_filter
        base = "arp" if preset == "arp-targets" else "ip"
        return f"{base} and ({host_filter})"
    return default_filter


def cmd_web(args: argparse.Namespace) -> None:
    # No need for root to start the web server, but jobs might need it.
    # We warn if not root.
    require_root()
    print(f"[*] Starting Web Control Plane on {args.host}:{args.port}")
    uvicorn.run("arpsurgeon.web.api:app", host=args.host, port=args.port, reload=False)


def cmd_campaign(args: argparse.Namespace) -> None:
    require_root()
    run_campaign(args.file, args.dry_run)


def cmd_interfaces(args: argparse.Namespace) -> None:
    default_iface = select_iface(args.iface)
    for entry in list_interfaces():
        suffix = " (default)" if default_iface and entry["iface"] == default_iface else ""
        print(f"{entry['iface']:>10} ip={entry['ip']:<15} mac={entry['mac']}{suffix}")


def cmd_observe(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    pcap_filter = _select_pcap_filter(args, "arp")
    observe(
        iface,
        args.duration,
        args.json,
        args.jsonl,
        args.pcap,
        pcap_filter,
        args.pcap_rotate_mb,
        args.pcap_rotate_seconds,
        args.verbose,
    )


def cmd_profile(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    pcap_filter = _select_pcap_filter(args, "arp")
    profile(
        iface,
        args.duration,
        args.oui_file,
        args.json,
        args.jsonl,
        args.pcap,
        pcap_filter,
        args.pcap_rotate_mb,
        args.pcap_rotate_seconds,
        args.verbose,
    )


def cmd_monitor(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    pcap_filter = _select_pcap_filter(args, "arp")
    monitor(
        iface,
        args.duration,
        args.jsonl,
        args.pcap,
        pcap_filter,
        args.storm_threshold,
        args.storm_window,
        args.pcap_rotate_mb,
        args.pcap_rotate_seconds,
        args.verbose,
    )


def cmd_dns_spoof(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    pcap_filter = _select_pcap_filter(args, "udp port 53")
    dns_spoof(
        iface,
        args.duration,
        args.hosts_file,
        args.default_ip,
        args.target or [],
        args.jsonl,
        args.pcap,
        pcap_filter,
        args.ttl,
        args.rate,
        args.dry_run,
        None,
        args.pcap_rotate_mb,
        args.pcap_rotate_seconds,
    )


def cmd_discover(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    results = arp_scan(args.cidr, iface, args.timeout, args.retry, args.oui_file, args.dry_run)
    if args.json:
        Path(args.json).write_text(json.dumps({"results": results}, indent=2), encoding="ascii")
    for entry in results:
        vendor = entry.get("vendor") or "unknown"
        print(f"{entry['ip']:>15} {entry['mac']:>17} vendor={vendor}")


def cmd_check(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    ips = _load_victims(args)
    results = check_targets(ips, iface, args.ping, args.timeout)
    if args.json:
        Path(args.json).write_text(
            json.dumps({"results": [result.__dict__ for result in results]}, indent=2),
            encoding="ascii",
        )
    for result in results:
        ping_status = "n/a"
        if result.icmp_ok is not None:
            ping_status = "ok" if result.icmp_ok else "fail"
        rtt = f"{result.rtt_ms:.1f}ms" if result.rtt_ms is not None else "-"
        print(
            f"{result.ip:>15} arp={'ok' if result.arp_ok else 'fail'} "
            f"ping={ping_status} rtt={rtt}"
        )


def cmd_snapshot(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    if args.cidr:
        entries = snapshot_cidr(args.cidr, iface, args.timeout, args.retry, args.dry_run)
    else:
        ips = _load_victims(args)
        entries = snapshot_ips(ips, iface, args.timeout, args.dry_run)
    Path(args.output).write_text(json.dumps({"entries": entries}, indent=2), encoding="ascii")
    print(f"snapshot entries={len(entries)} -> {args.output}")


def cmd_restore_snapshot(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    data = json.loads(Path(args.input).read_text(encoding="ascii"))
    entries = data.get("entries", [])
    restore_snapshot(entries, iface, args.count, args.dry_run)
    print(f"restored entries={len(entries)} from {args.input}")


def cmd_relay(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    victims = [_resolve_target(ip, iface, "victim") for ip in _load_victims(args)]
    gateway_ip = _resolve_gateway(args, iface)
    gateway = _resolve_target(gateway_ip, iface, "gateway")
    pcap_filter = _select_pcap_filter(
        args, "", hosts=[victim.ip for victim in victims] + [gateway.ip]
    )
    relay(
        victims,
        gateway,
        iface,
        args.duration,
        args.pcap,
        args.jsonl,
        pcap_filter or None,
        args.rate,
        args.dry_run,
        None,
        args.pcap_rotate_mb,
        args.pcap_rotate_seconds,
    )


def cmd_sever(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    sever_connection(
        args.target,
        args.port,
        iface,
        args.duration,
        args.dry_run,
    )


def cmd_report(args: argparse.Namespace) -> None:
    outputs = export_report(args.input, args.format, args.output)
    for output in outputs:
        print(output)


def cmd_poison(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    victims = [_resolve_target(ip, iface, "victim") for ip in _load_victims(args)]
    gateway_ip = _resolve_gateway(args, iface)
    gateway = _resolve_target(gateway_ip, iface, "gateway")
    stop_event = Event()
    jsonl_logger = JsonlLogger(args.jsonl)

    def handle_signal(_signum, _frame) -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, handle_signal)

    if args.forward:
        enable_ip_forwarding()
    try:
        _sleep_until(args.start_at, args.start_in)
        jsonl_logger.log(
            {
                "type": "poison_start",
                "victims": [victim.ip for victim in victims],
                "gateway": gateway.ip,
                "dry_run": args.dry_run,
            }
        )

        def on_cycle(cycle: int) -> None:
            jsonl_logger.log({"type": "poison_cycle", "cycle": cycle, "ts": time.time()})

        poison(
            victims,
            gateway,
            iface,
            args.interval,
            args.duration,
            args.stagger,
            args.jitter,
            args.dry_run,
            on_cycle=on_cycle if args.jsonl else None,
            should_stop=stop_event.is_set,
        )
    except KeyboardInterrupt:
        pass
    finally:
        if args.restore:
            restore(victims, gateway, iface, dry_run=args.dry_run)
            if args.verify:
                mismatches = verify_targets(victims, gateway, iface)
                for item in mismatches:
                    print(f"warning: {item}", file=sys.stderr)
        if args.forward:
            disable_ip_forwarding()
        jsonl_logger.log({"type": "poison_end", "ts": time.time()})
        jsonl_logger.close()


def cmd_restore(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    victims = [_resolve_target(ip, iface, "victim") for ip in _load_victims(args)]
    gateway_ip = _resolve_gateway(args, iface)
    gateway = _resolve_target(gateway_ip, iface, "gateway")
    restore(victims, gateway, iface, dry_run=args.dry_run)
    if args.verify:
        mismatches = verify_targets(victims, gateway, iface)
        for item in mismatches:
            print(f"warning: {item}", file=sys.stderr)


def cmd_mitm(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    victims = [_resolve_target(ip, iface, "victim") for ip in _load_victims(args)]
    gateway_ip = _resolve_gateway(args, iface)
    gateway = _resolve_target(gateway_ip, iface, "gateway")
    stop_event = Event()

    def handle_signal(_signum, _frame) -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, handle_signal)

    if args.forward:
        enable_ip_forwarding()

    threads = []

    def run_poison() -> None:
        poison(
            victims,
            gateway,
            iface,
            args.interval,
            None,
            args.stagger,
            args.jitter,
            args.dry_run,
            should_stop=stop_event.is_set,
        )

    threads.append(Thread(target=run_poison, daemon=True))

    if not args.no_relay:
        pcap_filter = _select_pcap_filter(
            args, "", hosts=[victim.ip for victim in victims] + [gateway.ip]
        )

        def run_relay() -> None:
            relay(
                victims,
                gateway,
                iface,
                None,
                args.relay_pcap,
                args.relay_jsonl,
                pcap_filter or None,
                args.relay_rate,
                args.dry_run,
                stop_event,
                args.pcap_rotate_mb,
                args.pcap_rotate_seconds,
            )

        threads.append(Thread(target=run_relay, daemon=True))

    if not args.no_dns:
        dns_filter = _select_pcap_filter(args, "udp port 53")

        def run_dns() -> None:
            dns_spoof(
                iface,
                None,
                args.dns_hosts_file,
                args.dns_default_ip,
                args.dns_target or [],
                args.dns_jsonl,
                args.dns_pcap,
                dns_filter,
                args.dns_ttl,
                args.dns_rate,
                args.dry_run,
                stop_event,
                args.pcap_rotate_mb,
                args.pcap_rotate_seconds,
            )

        threads.append(Thread(target=run_dns, daemon=True))

    for thread in threads:
        thread.start()

    try:
        if args.duration:
            time.sleep(args.duration)
            stop_event.set()
        else:
            while not stop_event.is_set():
                time.sleep(0.5)
    finally:
        stop_event.set()
        for thread in threads:
            thread.join(timeout=2)
        if args.restore:
            restore(victims, gateway, iface, dry_run=args.dry_run)
        if args.forward:
            disable_ip_forwarding()


def cmd_fuzz(args: argparse.Namespace) -> None:
    require_root()
    iface = _select_iface(args)
    fuzz_l2(iface, args.mode, args.rate, args.duration, args.dry_run)


def cmd_dashboard(args: argparse.Namespace) -> None:
    run_dashboard(args.input, args.refresh, args.max_events)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arpsurgeon",
        description="Precision-oriented ARP observation and manipulation toolkit.",
    )
    parser.add_argument("--iface", help="Network interface to use")
    parser.add_argument("--version", action="version", version="arpsurgeon 0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    interfaces_parser = subparsers.add_parser("interfaces", help="List interfaces and default route")
    interfaces_parser.set_defaults(func=cmd_interfaces)

    campaign_parser = subparsers.add_parser("campaign", help="Run an automated test campaign")
    campaign_parser.add_argument("--file", required=True, help="Campaign YAML file")
    campaign_parser.add_argument("--dry-run", action="store_true", help="Execute steps in dry-run mode")
    campaign_parser.set_defaults(func=cmd_campaign)

    web_parser = subparsers.add_parser("web", help="Start Web Control Plane (REST API + Dashboard)")
    web_parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    web_parser.add_argument("--port", type=int, default=8000, help="Bind port")
    web_parser.set_defaults(func=cmd_web)

    discover_parser = subparsers.add_parser("discover", help="ARP scan a CIDR for live hosts")
    discover_parser.add_argument("--cidr", required=True, help="CIDR to scan (e.g. 192.168.1.0/24)")
    discover_parser.add_argument("--timeout", type=float, default=2.0, help="Scan timeout per retry")
    discover_parser.add_argument("--retry", type=int, default=1, help="Number of retries")
    discover_parser.add_argument("--oui-file", help="CSV file with OUI,Vendor entries")
    discover_parser.add_argument("--json", help="Write results to JSON")
    discover_parser.add_argument("--dry-run", action="store_true", help="Skip sending packets")
    discover_parser.set_defaults(func=cmd_discover)

    check_parser = subparsers.add_parser("check", help="Check target reachability")
    check_parser.add_argument("--victim", action="append", help="Target IP (repeatable)")
    check_parser.add_argument("--victims-file", help="File with target IPs, one per line")
    check_parser.add_argument("--victims-json", help="JSON output from discover/profile")
    check_parser.add_argument("--victims-limit", type=int, help="Limit victim count")
    check_parser.add_argument("--ping", action="store_true", help="Send ICMP echo checks")
    check_parser.add_argument("--timeout", type=float, default=1.0, help="ICMP timeout seconds")
    check_parser.add_argument("--json", help="Write results to JSON")
    check_parser.set_defaults(func=cmd_check)

    observe_parser = subparsers.add_parser("observe", help="Observe ARP refresh behavior")
    observe_parser.add_argument("--duration", type=int, help="Seconds to observe (default: run until Ctrl+C)")
    observe_parser.add_argument("--json", help="Write observations to a JSON file")
    observe_parser.add_argument("--jsonl", help="Write observations to a JSONL timeline")
    observe_parser.add_argument("--pcap", help="Write captured packets to a pcap file")
    observe_parser.add_argument("--pcap-filter", help="Override BPF filter")
    observe_parser.add_argument(
        "--pcap-preset",
        choices=["arp", "dns", "ip"],
        help="Filter preset (used if --pcap-filter omitted)",
    )
    observe_parser.add_argument("--pcap-rotate-mb", type=int, help="Rotate pcap after MB")
    observe_parser.add_argument("--pcap-rotate-seconds", type=int, help="Rotate pcap after seconds")
    observe_parser.add_argument("--verbose", action="store_true", help="Print refresh intervals")
    observe_parser.set_defaults(func=cmd_observe)

    profile_parser = subparsers.add_parser("profile", help="Profile passive ARP table and refresh stats")
    profile_parser.add_argument("--duration", type=int, help="Seconds to observe (default: run until Ctrl+C)")
    profile_parser.add_argument("--oui-file", help="CSV file with OUI,Vendor entries")
    profile_parser.add_argument("--json", help="Write profile report to a JSON file")
    profile_parser.add_argument("--jsonl", help="Write refresh events to a JSONL timeline")
    profile_parser.add_argument("--pcap", help="Write captured packets to a pcap file")
    profile_parser.add_argument("--pcap-filter", help="Override BPF filter")
    profile_parser.add_argument(
        "--pcap-preset",
        choices=["arp", "dns", "ip"],
        help="Filter preset (used if --pcap-filter omitted)",
    )
    profile_parser.add_argument("--pcap-rotate-mb", type=int, help="Rotate pcap after MB")
    profile_parser.add_argument("--pcap-rotate-seconds", type=int, help="Rotate pcap after seconds")
    profile_parser.add_argument("--verbose", action="store_true", help="Print report to stdout")
    profile_parser.set_defaults(func=cmd_profile)

    monitor_parser = subparsers.add_parser("monitor", help="Monitor ARP anomalies")
    monitor_parser.add_argument("--duration", type=int, help="Seconds to monitor (default: run until Ctrl+C)")
    monitor_parser.add_argument("--jsonl", help="Write anomaly events to a JSONL timeline")
    monitor_parser.add_argument("--pcap", help="Write captured packets to a pcap file")
    monitor_parser.add_argument("--pcap-filter", help="Override BPF filter")
    monitor_parser.add_argument(
        "--pcap-preset",
        choices=["arp", "dns", "ip"],
        help="Filter preset (used if --pcap-filter omitted)",
    )
    monitor_parser.add_argument("--pcap-rotate-mb", type=int, help="Rotate pcap after MB")
    monitor_parser.add_argument("--pcap-rotate-seconds", type=int, help="Rotate pcap after seconds")
    monitor_parser.add_argument("--storm-threshold", type=int, default=200, help="Packets per window to alert")
    monitor_parser.add_argument("--storm-window", type=int, default=10, help="Seconds per storm window")
    monitor_parser.add_argument("--verbose", action="store_true", help="Print alerts")
    monitor_parser.set_defaults(func=cmd_monitor)

    dns_parser = subparsers.add_parser("dns-spoof", help="Spoof DNS A responses in a lab")
    dns_parser.add_argument("--duration", type=int, help="Seconds to run (default: run until Ctrl+C)")
    dns_parser.add_argument("--hosts-file", help="Hosts file format: IP domain [domain...]")
    dns_parser.add_argument("--default-ip", help="Fallback IP when no host rule matches")
    dns_parser.add_argument("--target", action="append", help="Only spoof requests from this source IP")
    dns_parser.add_argument("--ttl", type=int, default=60, help="TTL for spoofed answers")
    dns_parser.add_argument("--rate", type=int, help="Max spoofed responses per second")
    dns_parser.add_argument("--jsonl", help="Write spoof events to a JSONL file")
    dns_parser.add_argument("--pcap", help="Write captured packets to a pcap file")
    dns_parser.add_argument("--pcap-filter", help="Override BPF filter")
    dns_parser.add_argument(
        "--pcap-preset",
        choices=["dns", "ip"],
        help="Filter preset (used if --pcap-filter omitted)",
    )
    dns_parser.add_argument("--pcap-rotate-mb", type=int, help="Rotate pcap after MB")
    dns_parser.add_argument("--pcap-rotate-seconds", type=int, help="Rotate pcap after seconds")
    dns_parser.add_argument("--dry-run", action="store_true", help="Log actions without sending")
    dns_parser.set_defaults(func=cmd_dns_spoof)

    snapshot_parser = subparsers.add_parser("snapshot", help="Snapshot ARP cache mappings")
    snapshot_parser.add_argument("--cidr", help="CIDR to scan (optional)")
    snapshot_parser.add_argument("--victim", action="append", help="Target IP (repeatable)")
    snapshot_parser.add_argument("--victims-file", help="File with target IPs, one per line")
    snapshot_parser.add_argument("--victims-json", help="JSON output from discover/profile")
    snapshot_parser.add_argument("--victims-limit", type=int, help="Limit victim count")
    snapshot_parser.add_argument("--timeout", type=float, default=2.0, help="ARP timeout seconds")
    snapshot_parser.add_argument("--retry", type=int, default=1, help="Retries for CIDR scan")
    snapshot_parser.add_argument("--output", required=True, help="Output JSON file")
    snapshot_parser.add_argument("--dry-run", action="store_true", help="Skip sending packets")
    snapshot_parser.set_defaults(func=cmd_snapshot)

    restore_snapshot_parser = subparsers.add_parser(
        "restore-snapshot", help="Restore ARP cache from a snapshot file"
    )
    restore_snapshot_parser.add_argument("--input", required=True, help="Snapshot JSON file")
    restore_snapshot_parser.add_argument("--count", type=int, default=3, help="ARP reply count")
    restore_snapshot_parser.add_argument("--dry-run", action="store_true", help="Skip sending packets")
    restore_snapshot_parser.set_defaults(func=cmd_restore_snapshot)

    relay_parser = subparsers.add_parser("relay", help="Relay IP packets between victims and gateway")
    relay_parser.add_argument("--victim", action="append", help="Victim IP (repeatable)")
    relay_parser.add_argument("--victims-file", help="File with victim IPs, one per line")
    relay_parser.add_argument("--victims-json", help="JSON output from discover/profile")
    relay_parser.add_argument("--victims-limit", type=int, help="Limit victim count")
    relay_parser.add_argument("--gateway", help="Gateway IP (default: system gateway)")
    relay_parser.add_argument("--yes", action="store_true", help="Skip gateway confirmation prompt")
    relay_parser.add_argument("--duration", type=int, help="Seconds to relay (default: run until Ctrl+C)")
    relay_parser.add_argument("--rate", type=int, help="Max forwarded packets per second")
    relay_parser.add_argument("--jsonl", help="Write relay timeline to a JSONL file")
    relay_parser.add_argument("--pcap", help="Write captured packets to a pcap file")
    relay_parser.add_argument("--pcap-filter", help="Override BPF filter")
    relay_parser.add_argument(
        "--pcap-preset",
        choices=["arp-targets", "ip-targets", "ip"],
        help="Filter preset (used if --pcap-filter omitted)",
    )
    relay_parser.add_argument("--pcap-rotate-mb", type=int, help="Rotate pcap after MB")
    relay_parser.add_argument("--pcap-rotate-seconds", type=int, help="Rotate pcap after seconds")
    relay_parser.add_argument("--dry-run", action="store_true", help="Log actions without sending")
    relay_parser.set_defaults(func=cmd_relay)

    poison_parser = subparsers.add_parser("poison", help="Poison ARP caches for victim/gateway")
    poison_parser.add_argument("--victim", action="append", help="Victim IP (repeatable)")
    poison_parser.add_argument("--victims-file", help="File with victim IPs, one per line")
    poison_parser.add_argument("--victims-json", help="JSON output from discover/profile")
    poison_parser.add_argument("--victims-limit", type=int, help="Limit victim count")
    poison_parser.add_argument("--gateway", help="Gateway IP (default: system gateway)")
    poison_parser.add_argument("--yes", action="store_true", help="Skip gateway confirmation prompt")
    poison_parser.add_argument("--interval", type=float, default=2.0, help="Seconds between poisons")
    poison_parser.add_argument(
        "--stagger",
        type=float,
        default=0.0,
        help="Seconds to wait between victims in a cycle",
    )
    poison_parser.add_argument(
        "--jitter",
        type=float,
        default=0.0,
        help="Randomize interval by +/- seconds",
    )
    poison_parser.add_argument("--duration", type=float, help="Seconds to run (default: until Ctrl+C)")
    poison_parser.add_argument("--forward", action="store_true", help="Enable IP forwarding during poison")
    poison_parser.add_argument(
        "--restore",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Restore ARP tables when done (default: true)",
    )
    poison_parser.add_argument("--start-at", help="Start time (ISO 8601, local or TZ-aware)")
    poison_parser.add_argument("--start-in", type=float, help="Delay start by seconds")
    poison_parser.add_argument("--jsonl", help="Write poison timeline to a JSONL file")
    poison_parser.add_argument("--dry-run", action="store_true", help="Log actions without sending")
    poison_parser.add_argument("--verify", action="store_true", help="Verify MACs after restore")
    poison_parser.set_defaults(func=cmd_poison)

    restore_parser = subparsers.add_parser("restore", help="Restore ARP caches for victim/gateway")
    restore_parser.add_argument("--victim", action="append", help="Victim IP (repeatable)")
    restore_parser.add_argument("--victims-file", help="File with victim IPs, one per line")
    restore_parser.add_argument("--victims-json", help="JSON output from discover/profile")
    restore_parser.add_argument("--victims-limit", type=int, help="Limit victim count")
    restore_parser.add_argument("--gateway", help="Gateway IP (default: system gateway)")
    restore_parser.add_argument("--yes", action="store_true", help="Skip gateway confirmation prompt")
    restore_parser.add_argument("--dry-run", action="store_true", help="Skip sending packets")
    restore_parser.add_argument("--verify", action="store_true", help="Verify MACs after restore")
    restore_parser.set_defaults(func=cmd_restore)

    sever_parser = subparsers.add_parser("sever", help="Sever TCP connections via RST injection")
    sever_parser.add_argument("--target", required=True, help="Target IP address")
    sever_parser.add_argument("--port", type=int, help="Target TCP port (optional)")
    sever_parser.add_argument("--duration", type=int, help="Seconds to run (default: until Ctrl+C)")
    sever_parser.add_argument("--dry-run", action="store_true", help="Log actions without sending")
    sever_parser.set_defaults(func=cmd_sever)

    report_parser = subparsers.add_parser("report", help="Export JSON/JSONL reports to CSV/Markdown")
    report_parser.add_argument("--input", required=True, help="Input JSON or JSONL file")
    report_parser.add_argument("--format", choices=["csv", "md", "html", "graph"], default="md", help="Output format")
    report_parser.add_argument("--output", required=True, help="Output path (file or dir)")
    report_parser.set_defaults(func=cmd_report)

    mitm_parser = subparsers.add_parser("mitm", help="Run poison + relay + dns-spoof together")
    mitm_parser.add_argument("--victim", action="append", help="Victim IP (repeatable)")
    mitm_parser.add_argument("--victims-file", help="File with victim IPs, one per line")
    mitm_parser.add_argument("--victims-json", help="JSON output from discover/profile")
    mitm_parser.add_argument("--victims-limit", type=int, help="Limit victim count")
    mitm_parser.add_argument("--gateway", help="Gateway IP (default: system gateway)")
    mitm_parser.add_argument("--yes", action="store_true", help="Skip gateway confirmation prompt")
    mitm_parser.add_argument("--interval", type=float, default=2.0, help="Seconds between poisons")
    mitm_parser.add_argument("--stagger", type=float, default=0.0, help="Seconds between victims")
    mitm_parser.add_argument("--jitter", type=float, default=0.0, help="Randomize interval by +/- seconds")
    mitm_parser.add_argument("--duration", type=int, help="Seconds to run (default: until Ctrl+C)")
    mitm_parser.add_argument("--forward", action="store_true", help="Enable IP forwarding during MITM")
    mitm_parser.add_argument("--restore", action=argparse.BooleanOptionalAction, default=True)
    mitm_parser.add_argument("--dry-run", action="store_true", help="Log actions without sending")
    mitm_parser.add_argument("--no-relay", action="store_true", help="Disable relay")
    mitm_parser.add_argument("--relay-rate", type=int, help="Max forwarded packets per second")
    mitm_parser.add_argument("--relay-jsonl", help="Write relay timeline to a JSONL file")
    mitm_parser.add_argument("--relay-pcap", help="Write relay packets to a pcap file")
    mitm_parser.add_argument("--no-dns", action="store_true", help="Disable DNS spoofing")
    mitm_parser.add_argument("--dns-hosts-file", help="Hosts file format: IP domain [domain...]")
    mitm_parser.add_argument("--dns-default-ip", help="Fallback IP when no host rule matches")
    mitm_parser.add_argument("--dns-target", action="append", help="Only spoof requests from this source IP")
    mitm_parser.add_argument("--dns-ttl", type=int, default=60, help="TTL for spoofed answers")
    mitm_parser.add_argument("--dns-rate", type=int, help="Max spoofed responses per second")
    mitm_parser.add_argument("--dns-jsonl", help="Write DNS spoof timeline to a JSONL file")
    mitm_parser.add_argument("--dns-pcap", help="Write DNS spoof packets to a pcap file")
    mitm_parser.add_argument("--pcap-filter", help="Override BPF filter")
    mitm_parser.add_argument(
        "--pcap-preset",
        choices=["arp-targets", "ip-targets", "ip", "dns"],
        help="Filter preset (used if --pcap-filter omitted)",
    )
    mitm_parser.add_argument("--pcap-rotate-mb", type=int, help="Rotate pcap after MB")
    mitm_parser.add_argument("--pcap-rotate-seconds", type=int, help="Rotate pcap after seconds")
    mitm_parser.set_defaults(func=cmd_mitm)

    fuzz_parser = subparsers.add_parser("fuzz", help="Fuzz L2 protocols for stress testing")
    fuzz_parser.add_argument(
        "--mode", 
        choices=["random", "arp_opcode", "ether_type", "mac_flood", "malformed", "bogus_ip"], 
        default="random", 
        help="Fuzzing strategy"
    )
    fuzz_parser.add_argument("--rate", type=int, default=10, help="Packets per second")
    fuzz_parser.add_argument("--duration", type=int, help="Seconds to run")
    fuzz_parser.add_argument("--dry-run", action="store_true", help="Log actions without sending")
    fuzz_parser.set_defaults(func=cmd_fuzz)

    dashboard_parser = subparsers.add_parser("dashboard", help="Live TUI for JSONL event files")
    dashboard_parser.add_argument("--input", required=True, help="JSONL file to watch")
    dashboard_parser.add_argument("--refresh", type=float, default=0.5, help="Refresh interval seconds")
    dashboard_parser.add_argument("--max-events", type=int, default=20, help="Events shown")
    dashboard_parser.set_defaults(func=cmd_dashboard)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Print Banner
    banner_path = Path("Banner.txt")
    if banner_path.exists():
        print(banner_path.read_text(encoding="utf-8"))
    
    parser = build_parser()
    config = load_config()
    apply_config(parser, config)
    args = parser.parse_args(argv)
    if args.iface:
        conf.iface = args.iface
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
