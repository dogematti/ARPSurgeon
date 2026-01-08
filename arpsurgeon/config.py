from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict

if sys.version_info >= (3, 11):
    import tomllib
else:
    # Fallback for older python versions if needed, though project uses 3.14
    # We will assume tomllib is available as per requirements
    import tomllib


def load_config() -> Dict[str, Any]:
    """
    Load configuration from:
    1. ./arpsurgeon.toml
    2. ~/.arpsurgeon.toml
    
    Returns a dictionary of configuration values.
    """
    paths = [
        Path.home() / ".arpsurgeon.toml",
        Path("arpsurgeon.toml"),
    ]
    
    config = {}
    for path in paths:
        if path.exists():
            try:
                with path.open("rb") as f:
                    data = tomllib.load(f)
                    # We merge configs, allowing local file to override global
                    _deep_update(config, data)
            except Exception as e:
                print(f"warning: failed to load config {path}: {e}", file=sys.stderr)
    
    return config


def _deep_update(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, dict) and key in target and isinstance(target[key], dict):
            _deep_update(target[key], value)
        else:
            target[key] = value


def apply_config(parser: argparse.ArgumentParser, config: Dict[str, Any]) -> None:
    """
    Apply configuration values to the argument parser defaults.
    The config structure should match the CLI argument names.
    
    Example config:
    [global]
    iface = "eth0"
    
    [monitor]
    storm_threshold = 300
    
    This function will flatten the config and map it to argument destinations.
    """
    defaults = {}
    
    # Global settings
    if "global" in config:
        defaults.update(config["global"])
        
    # Command-specific settings (if they match argument names)
    # Since argparse has a flat namespace for the parsed args (mostly),
    # we can try to apply command specific defaults if we know the command.
    # However, set_defaults works globally for the parser.
    # Subparsers complicate this. We might need to traverse subparsers.
    
    # For now, let's just flatten everything from valid sections
    for section, values in config.items():
        if section == "global":
            continue
        if isinstance(values, dict):
            defaults.update(values)
            
    parser.set_defaults(**defaults)
