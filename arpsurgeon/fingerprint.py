from __future__ import annotations

from typing import Optional, Tuple

# Simple signature database
# (Initial TTL, Window Size) -> OS Family
# Window Size can be exact or a typical multiple.
# This is a heuristic and not 100% accurate.

# Common Initial TTLs:
# 64: Linux, macOS, Android, iOS, BSD
# 128: Windows
# 255: Cisco, Solaris

# Common Window Sizes:
# 65535: generic
# 64240: Linux
# 65535: macOS/iOS often use 65535 or scaling
# 8192: Windows (older)
# 64240: Windows 10/11 often varies

SIGNATURES = [
    (64, None, "Linux/macOS/Unix"),
    (128, None, "Windows"),
    (255, None, "Cisco/Solaris"),
    (32, None, "Windows 95/98/NT (Ancient)"),
]

# Option 55 (Parameter Request List) fingerprints
# Format: tuple(sorted(option_codes)) -> "OS Name"
# Note: Real fingerprints are order-sensitive, but sorting helps matching variations if we don't have a huge DB.
# However, precise matching requires preserving order. Let's try precise string matching of the comma-joined list first.
DHCP_SIGNATURES = {
    # Windows 10/11 common
    (1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 252, 43): "Windows 10/11",
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252): "Windows 10/11",
    # macOS (recent)
    (1, 121, 3, 6, 15, 119, 252): "macOS 10.11+",
    (1, 3, 6, 15, 119, 252): "macOS",
    # iOS
    (1, 121, 3, 6, 15, 119, 252): "iOS 12+",
    (1, 3, 6, 15, 119, 252): "iOS",
    # Android
    (1, 33, 3, 6, 15, 28, 51, 58, 59): "Android",
    (1, 3, 6, 15, 26, 28, 51, 58, 59, 43): "Android",
    # Linux (generic dhclient)
    (1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42): "Linux (dhclient)",
}

def guess_os_dhcp(option55: list[int]) -> Optional[str]:
    """
    Guess OS based on DHCP Option 55 (Parameter Request List).
    Input should be the list of requested option codes in order.
    """
    # Try exact match first
    sig = tuple(option55)
    if sig in DHCP_SIGNATURES:
        return DHCP_SIGNATURES[sig]
    
    # Try sorted match (less precise but catches variations)
    sig_sorted = tuple(sorted(option55))
    # We'd need a secondary map for sorted keys if we wanted to support this efficiently.
    # For now, let's just stick to exact matches or partial.
    
    return None

def guess_os(ttl: int, window: Optional[int] = None) -> str:
    """
    Guess the OS family based on TTL and optionally TCP Window Size.
    """
    # Normalize TTL to nearest power of 2 or common boundary
    # This handles hops decrementing the TTL.
    initial_ttl = 0
    if ttl <= 32:
        initial_ttl = 32
    elif ttl <= 64:
        initial_ttl = 64
    elif ttl <= 128:
        initial_ttl = 128
    elif ttl <= 255:
        initial_ttl = 255
    else:
        return "Unknown"

    candidate = "Unknown"
    for sig_ttl, sig_win, name in SIGNATURES:
        if sig_ttl == initial_ttl:
            candidate = name
            break
            
    # Refine based on window size if available (and if we have signatures for it)
    # For now, TTL is the primary discriminator for simple passive fingerprinting.
    
    return candidate
