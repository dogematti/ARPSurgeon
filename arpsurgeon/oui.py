from __future__ import annotations

from typing import Dict, Optional


def _normalize(prefix: str) -> str:
    return prefix.replace("-", "").replace(":", "").upper()


def load_oui_map(path: Optional[str]) -> Dict[str, str]:
    if not path:
        return {}
    oui_map: Dict[str, str] = {}
    with open(path, "r", encoding="ascii", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [part.strip() for part in line.split(",", 1)]
            if len(parts) != 2:
                continue
            prefix = _normalize(parts[0])
            if len(prefix) < 6:
                continue
            oui_map[prefix[:6]] = parts[1]
    return oui_map


def lookup_vendor(mac: str, oui_map: Dict[str, str]) -> Optional[str]:
    if not mac or not oui_map:
        return None
    prefix = _normalize(mac)[:6]
    return oui_map.get(prefix)
