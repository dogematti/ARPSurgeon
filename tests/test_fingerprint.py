"""Tests for arpsurgeon.fingerprint (OS guessing from TTL / DHCP)."""
from __future__ import annotations

import pytest

from arpsurgeon.fingerprint import DHCP_SIGNATURES, guess_os, guess_os_dhcp


class TestGuessOS:
    def test_guess_os_exact_linux(self):
        """TTL=64 should map to the Linux/macOS/Unix family."""
        result = guess_os(64)
        assert "Linux" in result or "macOS" in result or "Unix" in result

    def test_guess_os_exact_windows(self):
        """TTL=128 should map to the Windows family."""
        result = guess_os(128)
        assert "Windows" in result

    def test_guess_os_normalized_linux(self):
        """TTL=60 (hops decremented from initial 64) should normalize to 64."""
        result = guess_os(60)
        assert "Linux" in result or "macOS" in result or "Unix" in result

    def test_guess_os_normalized_windows(self):
        """TTL=120 (hops decremented from initial 128) should normalize to 128."""
        result = guess_os(120)
        assert "Windows" in result

    def test_guess_os_cisco(self):
        """TTL=255 should map to Cisco/Solaris."""
        result = guess_os(255)
        assert "Cisco" in result or "Solaris" in result

    def test_guess_os_windows_ancient(self):
        """TTL=32 should map to Windows 95/98/NT."""
        result = guess_os(32)
        assert "Windows" in result
        assert "95" in result or "98" in result or "NT" in result

    def test_guess_os_unknown_high_ttl(self):
        """TTL values above 255 should return 'Unknown'."""
        result = guess_os(999)
        assert result == "Unknown"

    def test_guess_os_low_ttl_normalizes_to_32(self):
        """Very low TTL (e.g. 1) should normalize to 32 and match the Windows 95/98 entry."""
        result = guess_os(1)
        # TTL <= 32 normalizes to 32 which matches "Windows 95/98/NT (Ancient)"
        assert "Windows" in result

    def test_guess_os_with_window_still_matches(self):
        """Providing a window parameter should not break the TTL-based match."""
        result = guess_os(64, window=65535)
        assert "Linux" in result or "macOS" in result or "Unix" in result

    @pytest.mark.parametrize(
        "ttl,expected_fragment",
        [
            (64, "Linux"),
            (128, "Windows"),
            (255, "Cisco"),
            (32, "95"),
        ],
    )
    def test_guess_os_parametrized(self, ttl, expected_fragment):
        result = guess_os(ttl)
        assert expected_fragment in result


class TestGuessOsDhcp:
    def test_guess_os_dhcp_known(self):
        """A known DHCP Option 55 signature should return the associated OS name."""
        # Pick the first known signature from DHCP_SIGNATURES
        sig, expected_os = next(iter(DHCP_SIGNATURES.items()))
        result = guess_os_dhcp(list(sig))
        assert result == expected_os

    def test_guess_os_dhcp_unknown(self):
        """An unknown Option 55 list should return None."""
        result = guess_os_dhcp([99, 98, 97, 96])
        assert result is None
