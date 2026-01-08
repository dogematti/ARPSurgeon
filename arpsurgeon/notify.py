from __future__ import annotations

import json
import sys
import threading
from typing import Any
from urllib import request, error

from arpsurgeon.config import load_config

def _post_json(url: str, data: dict) -> None:
    req = request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "ARPSurgeon/1.0"},
    )
    try:
        with request.urlopen(req, timeout=5) as resp:
            pass
    except error.URLError as e:
        print(f"warning: notification failed: {e}", file=sys.stderr)

def send_notification(event_type: str, payload: dict[str, Any]) -> None:
    """
    Send a notification based on configuration.
    This runs in a background thread to avoid blocking the main loop.
    """
    config = load_config()
    notify_cfg = config.get("notifications", {})
    
    if not notify_cfg.get("enabled", False):
        return

    # Prepare message
    message = f"[{event_type.upper()}] "
    if event_type == "storm":
        message += f"ARP Storm detected: {payload.get('count')} packets in {payload.get('window')}s"
    elif event_type == "conflict":
        message += f"IP Conflict: {payload.get('ip')} claimed by {payload.get('new_mac')} (was {payload.get('old_mac')})"
    elif event_type == "gratuitous":
        message += f"Gratuitous ARP: {payload.get('ip')} is at {payload.get('mac')}"
    else:
        message += str(payload)

    # Discord
    discord_url = notify_cfg.get("discord_webhook")
    if discord_url:
        t = threading.Thread(
            target=_post_json,
            args=(discord_url, {"content": message, "username": "ARPSurgeon"}),
            daemon=True
        )
        t.start()
    
    # Slack
    slack_url = notify_cfg.get("slack_webhook")
    if slack_url:
        t = threading.Thread(
            target=_post_json,
            args=(slack_url, {"text": message}),
            daemon=True
        )
        t.start()
        
    # Generic Webhook
    generic_url = notify_cfg.get("webhook_url")
    if generic_url:
        t = threading.Thread(
            target=_post_json,
            args=(generic_url, {"event": event_type, "payload": payload, "message": message}),
            daemon=True
        )
        t.start()
