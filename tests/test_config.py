"""Tests for arpsurgeon.config (TOML loading, deep merge, apply_config)."""
from __future__ import annotations

import argparse

import pytest

from arpsurgeon.config import _deep_update, apply_config, load_config


class TestDeepUpdate:
    def test_deep_update_flat(self):
        """Simple key override: source value replaces target value."""
        target = {"a": 1, "b": 2}
        _deep_update(target, {"b": 99})
        assert target == {"a": 1, "b": 99}

    def test_deep_update_nested(self):
        """Nested dicts should be merged recursively."""
        target = {"section": {"key1": "old", "key2": "keep"}}
        _deep_update(target, {"section": {"key1": "new"}})
        assert target["section"]["key1"] == "new"
        assert target["section"]["key2"] == "keep"

    def test_deep_update_new_keys(self):
        """Source can add entirely new keys to the target."""
        target = {"a": 1}
        _deep_update(target, {"b": 2, "c": {"nested": True}})
        assert target["b"] == 2
        assert target["c"]["nested"] is True


class TestLoadConfig:
    def test_load_config_no_files(self, tmp_path, monkeypatch):
        """When no config files exist, load_config should return an empty dict."""
        # Change cwd to a temp dir with no toml files
        monkeypatch.chdir(tmp_path)
        # Also ensure the home config doesn't interfere
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "fakehome")
        config = load_config()
        assert config == {}


class TestApplyConfig:
    def test_apply_config_sets_defaults(self):
        """apply_config should set parser defaults from global and section config."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--iface", default=None)
        parser.add_argument("--storm-threshold", type=int, default=200)

        config = {
            "global": {"iface": "eth0"},
            "monitor": {"storm_threshold": 50},
        }
        apply_config(parser, config)

        args = parser.parse_args([])
        assert args.iface == "eth0"
        assert args.storm_threshold == 50
