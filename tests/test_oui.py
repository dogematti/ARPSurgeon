"""Tests for arpsurgeon.oui (OUI / vendor lookup)."""
from __future__ import annotations

import pytest

from arpsurgeon.oui import load_oui_map, lookup_vendor


class TestLoadOuiMap:
    def test_load_oui_map_none_returns_empty(self):
        """Passing None as path should return an empty dict."""
        assert load_oui_map(None) == {}

    def test_load_oui_map_valid_file(self, tmp_path):
        """A well-formed OUI file should be loaded correctly."""
        oui_file = tmp_path / "oui.csv"
        oui_file.write_text(
            "AABBCC,TestVendor Inc\n"
            "112233,AnotherVendor\n"
        )
        oui_map = load_oui_map(str(oui_file))
        assert oui_map["AABBCC"] == "TestVendor Inc"
        assert oui_map["112233"] == "AnotherVendor"
        assert len(oui_map) == 2

    def test_load_oui_map_skips_comments(self, tmp_path):
        """Lines starting with '#' should be ignored."""
        oui_file = tmp_path / "oui.csv"
        oui_file.write_text(
            "# This is a comment\n"
            "AABBCC,TestVendor\n"
            "# Another comment\n"
        )
        oui_map = load_oui_map(str(oui_file))
        assert len(oui_map) == 1
        assert "AABBCC" in oui_map

    def test_load_oui_map_skips_short_prefix(self, tmp_path):
        """Prefixes shorter than 6 hex characters should be skipped."""
        oui_file = tmp_path / "oui.csv"
        oui_file.write_text(
            "AABB,ShortVendor\n"
            "AABBCC,GoodVendor\n"
        )
        oui_map = load_oui_map(str(oui_file))
        assert len(oui_map) == 1
        assert "AABBCC" in oui_map


class TestLookupVendor:
    @pytest.fixture
    def oui_map(self):
        return {"AABBCC": "TestVendor", "112233": "AnotherVendor"}

    def test_lookup_vendor_found(self, oui_map):
        """A known MAC prefix should return the vendor string."""
        assert lookup_vendor("aa:bb:cc:dd:ee:ff", oui_map) == "TestVendor"

    def test_lookup_vendor_not_found(self, oui_map):
        """An unknown MAC prefix should return None."""
        assert lookup_vendor("ff:ff:ff:ff:ff:ff", oui_map) is None

    def test_lookup_vendor_normalizes_mac(self, oui_map):
        """lookup_vendor should handle colons, dashes, and mixed case."""
        assert lookup_vendor("aa:bb:cc:dd:ee:ff", oui_map) == "TestVendor"
        assert lookup_vendor("AA-BB-CC-DD-EE-FF", oui_map) == "TestVendor"
        assert lookup_vendor("AaBbCcDdEeFf", oui_map) == "TestVendor"
