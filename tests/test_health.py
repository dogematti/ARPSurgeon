"""Tests for arpsurgeon.health (ARP + ICMP health checks).

All scapy calls are mocked so tests run without root or network access.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# We must mock scapy imports before importing the module under test.
# The module does `from scapy.all import ...` at the top level, and
# arpsurgeon.arp (imported by health) also imports scapy.  We patch
# the already-imported names at the module level.

from arpsurgeon.arp import ArpTarget


class TestCheckTargets:
    @patch("arpsurgeon.health.resolve_mac")
    def test_check_targets_arp_ok(self, mock_resolve):
        """When resolve_mac returns a MAC, arp_ok should be True."""
        from arpsurgeon.health import check_targets

        mock_resolve.return_value = "aa:bb:cc:dd:ee:ff"
        results = check_targets(["10.0.0.1"], iface=None, ping=False, timeout=1.0)
        assert len(results) == 1
        assert results[0].arp_ok is True
        assert results[0].mac == "aa:bb:cc:dd:ee:ff"

    @patch("arpsurgeon.health.resolve_mac")
    def test_check_targets_arp_fail(self, mock_resolve):
        """When resolve_mac returns None, arp_ok should be False."""
        from arpsurgeon.health import check_targets

        mock_resolve.return_value = None
        results = check_targets(["10.0.0.1"], iface=None, ping=False, timeout=1.0)
        assert len(results) == 1
        assert results[0].arp_ok is False
        assert results[0].mac is None

    @patch("arpsurgeon.health.ping_host")
    @patch("arpsurgeon.health.resolve_mac")
    def test_check_targets_with_ping(self, mock_resolve, mock_ping):
        """When ping=True, icmp_ok and rtt_ms should be populated."""
        from arpsurgeon.health import check_targets

        mock_resolve.return_value = "aa:bb:cc:dd:ee:ff"
        mock_ping.return_value = 5.2  # 5.2 ms RTT
        results = check_targets(["10.0.0.1"], iface=None, ping=True, timeout=1.0)
        assert results[0].icmp_ok is True
        assert results[0].rtt_ms == pytest.approx(5.2)

    @patch("arpsurgeon.health.sr1")
    def test_ping_host_timeout(self, mock_sr1):
        """When sr1 returns None (timeout), ping_host should return None."""
        from arpsurgeon.health import ping_host

        mock_sr1.return_value = None
        result = ping_host("10.0.0.1", iface=None, timeout=0.5)
        assert result is None


class TestToTargets:
    def test_to_targets_filters_none_mac(self):
        """Results with mac=None should be excluded from the output list."""
        from arpsurgeon.health import HealthResult, to_targets

        results = [
            HealthResult(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff", arp_ok=True, icmp_ok=None, rtt_ms=None),
            HealthResult(ip="10.0.0.2", mac=None, arp_ok=False, icmp_ok=None, rtt_ms=None),
            HealthResult(ip="10.0.0.3", mac="11:22:33:44:55:66", arp_ok=True, icmp_ok=None, rtt_ms=None),
        ]
        targets = to_targets(results)
        assert len(targets) == 2
        assert all(isinstance(t, ArpTarget) for t in targets)
        ips = [t.ip for t in targets]
        assert "10.0.0.2" not in ips
