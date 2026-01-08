import os
import platform
import re
import subprocess
import sys
from typing import Optional

from scapy.all import conf, get_if_addr, get_if_hwaddr, get_if_list  # type: ignore


def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("warning: this command typically requires root privileges", file=sys.stderr)


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def enable_ip_forwarding() -> None:
    system = platform.system().lower()
    if system == "linux":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="ascii") as handle:
                handle.write("1")
            return
        except OSError:
            _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            return
    if system == "darwin":
        _run(["sysctl", "-w", "net.inet.ip.forwarding=1"])


def disable_ip_forwarding() -> None:
    system = platform.system().lower()
    if system == "linux":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="ascii") as handle:
                handle.write("0")
            return
        except OSError:
            _run(["sysctl", "-w", "net.ipv4.ip_forward=0"])
            return
    if system == "darwin":
        _run(["sysctl", "-w", "net.inet.ip.forwarding=0"])


def list_interfaces() -> list[dict[str, str]]:
    interfaces = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "unknown"
        try:
            mac = get_if_hwaddr(iface)
        except Exception:
            mac = "unknown"
        interfaces.append({"iface": iface, "ip": ip, "mac": mac})
    return interfaces


def _parse_route() -> tuple[Optional[str], Optional[str]]:
    try:
        route = conf.route.route("0.0.0.0")
    except Exception:
        return None, None
    iface = None
    gateway = None
    for item in route:
        if isinstance(item, str) and item in get_if_list():
            iface = item
        elif isinstance(item, str) and re.match(r"^\d+\.\d+\.\d+\.\d+$", item):
            if item != "0.0.0.0":
                gateway = item
    return iface, gateway


def default_route_iface() -> Optional[str]:
    iface, _ = _parse_route()
    return iface


def default_gateway_ip() -> Optional[str]:
    _, gateway = _parse_route()
    return gateway


def validate_iface(iface: Optional[str]) -> Optional[str]:
    if not iface:
        return None
    if iface not in get_if_list():
        raise SystemExit(f"unknown interface: {iface}")
    return iface


def select_iface(requested: Optional[str]) -> Optional[str]:
    if requested:
        return validate_iface(requested)
    return default_route_iface()
