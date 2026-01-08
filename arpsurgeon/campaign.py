from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, Dict

import yaml

# We defer imports of cli commands to avoid circular dependency
# as cli.py imports this module.

def run_campaign(campaign_file: str, dry_run: bool = False, stop_event: Any = None) -> None:
    path = Path(campaign_file)
    if not path.exists():
        raise RuntimeError(f"Campaign file not found: {path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise RuntimeError(f"Invalid YAML: {e}")

    name = data.get("name", "Unnamed Campaign")
    steps = data.get("steps", [])

    print(f"[*] Starting Campaign: {name}")
    print(f"[*] Steps: {len(steps)}")

    # Import commands here to prevent circular import
    from arpsurgeon import cli

    # Map action names to command functions
    # We use the same names as CLI subcommands
    COMMAND_MAP = {
        "discover": cli.cmd_discover,
        "observe": cli.cmd_observe,
        "profile": cli.cmd_profile,
        "monitor": cli.cmd_monitor,
        "dns-spoof": cli.cmd_dns_spoof,
        "snapshot": cli.cmd_snapshot,
        "restore-snapshot": cli.cmd_restore_snapshot,
        "check": cli.cmd_check,
        "poison": cli.cmd_poison,
        "relay": cli.cmd_relay,
        "restore": cli.cmd_restore,
        "mitm": cli.cmd_mitm,
        "report": cli.cmd_report,
        "sever": cli.cmd_sever,
        "fuzz": cli.cmd_fuzz,
    }

    # Default namespace with all possible args set to None/False
    # This prevents AttributeError when a command checks for an arg that wasn't in the step
    # We can inspect the parser defaults, but a comprehensive defaults dict is easier for now.
    base_defaults = {
        "iface": None,
        "dry_run": dry_run,  # Global dry_run override if set
        # Common
        "verbose": False,
        "json": None,
        "jsonl": None,
        "pcap": None,
        "pcap_filter": None,
        "pcap_preset": None,
        "pcap_rotate_mb": None,
        "pcap_rotate_seconds": None,
        "yes": True, # Assume yes for automated campaigns
        # Discover
        "cidr": None,
        "timeout": 2.0,
        "retry": 1,
        "oui_file": None,
        # Poison/MITM
        "victim": None,
        "victims_file": None,
        "victims_json": None,
        "victims_limit": None,
        "gateway": None,
        "interval": 2.0,
        "stagger": 0.0,
        "jitter": 0.0,
        "duration": None,
        "forward": False,
        "restore": True,
        "start_at": None,
        "start_in": None,
        "verify": False,
        "no_relay": False,
        "no_dns": False,
        "relay_rate": None,
        "relay_jsonl": None,
        "relay_pcap": None,
        "dns_hosts_file": None,
        "dns_default_ip": None,
        "dns_target": None,
        "dns_ttl": 60,
        "dns_rate": None,
        "dns_jsonl": None,
        "dns_pcap": None,
        # Monitor
        "storm_threshold": 200,
        "storm_window": 10,
        # Sever
        "target": None,
        "port": None,
        # Fuzz
        "mode": "random",
        "rate": 10,
        # Report
        "input": None,
        "format": "md",
        "output": None,
        # Check
        "ping": False,
        # Snapshot
        "count": 3,
    }

    for i, step in enumerate(steps, 1):
        if stop_event and stop_event.is_set():
            print("[*] Campaign stopped by user.")
            break

        action = step.get("action")
        step_name = step.get("name", action)
        args_dict = step.get("args", {})
        
        # Handle simple pauses
        if action == "sleep":
            duration = float(args_dict.get("duration", 0))
            print(f"[*] Step {i}: Sleep {duration}s")
            # Sleep in chunks to allow interruption
            end_time = time.time() + duration
            while time.time() < end_time:
                if stop_event and stop_event.is_set():
                    break
                time.sleep(0.1)
            continue

        if action not in COMMAND_MAP:
            print(f"[!] Warning: Unknown action '{action}' in step {i}. Skipping.")
            continue

        func = COMMAND_MAP[action]
        
        # Merge defaults with step args
        # Priority: Step Args > Base Defaults
        # Also ensure 'dry_run' propagates if globally set
        namespace_dict = base_defaults.copy()
        namespace_dict.update(args_dict)
        if dry_run:
            namespace_dict["dry_run"] = True
            
        # Convert to Namespace
        args = argparse.Namespace(**namespace_dict)
        
        print(f"[*] Step {i}: {step_name} ({action})")
        try:
            func(args)
        except SystemExit as e:
            if e.code != 0:
                print(f"[!] Step {i} failed with exit code {e.code}. Aborting campaign.")
                raise RuntimeError(f"Step {i} failed")
        except Exception as e:
             print(f"[!] Step {i} encountered error: {e}. Aborting campaign.")
             raise RuntimeError(f"Step {i} error: {e}")
        
        print(f"[*] Step {i} completed.\n")

    print("[*] Campaign finished successfully.")
