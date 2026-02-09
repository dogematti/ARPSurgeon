"""Tests for arpsurgeon.storage.Database."""
from __future__ import annotations

import sqlite3
import time

import pytest

from arpsurgeon.storage import Database


class TestInitDB:
    def test_init_creates_tables(self, tmp_db: Database):
        """All three tables (hosts, events, refresh_stats) should exist after init."""
        conn = sqlite3.connect(tmp_db.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = sorted(row[0] for row in cursor.fetchall())
        conn.close()
        assert "events" in tables
        assert "hosts" in tables
        assert "refresh_stats" in tables


class TestUpsertHost:
    def test_upsert_host_insert(self, tmp_db: Database, sample_host: dict):
        """Inserting a new host should make it appear in get_hosts()."""
        tmp_db.upsert_host(sample_host)
        hosts, total = tmp_db.get_hosts()
        assert total == 1
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.1.100"
        assert hosts[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert hosts[0]["hostname"] == "test-host"
        assert hosts[0]["vendor"] == "TestVendor"
        assert hosts[0]["os"] == "Linux"
        assert hosts[0]["count"] == 1

    def test_upsert_host_update_merges(self, tmp_db: Database, sample_host: dict):
        """Updating an existing host should merge fields, preferring new non-empty values."""
        tmp_db.upsert_host(sample_host)
        updated = {
            "ip": "192.168.1.100",
            "mac": "11:22:33:44:55:66",
            "hostname": "new-hostname",
            "vendor": "NewVendor",
            "os": "Windows",
        }
        tmp_db.upsert_host(updated)

        hosts, _ = tmp_db.get_hosts()
        assert len(hosts) == 1
        host = hosts[0]
        assert host["mac"] == "11:22:33:44:55:66"
        assert host["hostname"] == "new-hostname"
        assert host["vendor"] == "NewVendor"
        assert host["os"] == "Windows"

    def test_upsert_host_count_increments(self, tmp_db: Database, sample_host: dict):
        """Two upserts for the same IP should yield count == 2."""
        tmp_db.upsert_host(sample_host)
        tmp_db.upsert_host(sample_host)
        hosts, _ = tmp_db.get_hosts()
        assert hosts[0]["count"] == 2

    def test_upsert_host_preserves_nonempty(self, tmp_db: Database, sample_host: dict):
        """Updating with an empty hostname should keep the existing hostname."""
        tmp_db.upsert_host(sample_host)
        tmp_db.upsert_host({"ip": "192.168.1.100", "hostname": ""})
        hosts, _ = tmp_db.get_hosts()
        assert hosts[0]["hostname"] == "test-host"

    def test_upsert_host_dhcp_os_priority(self, tmp_db: Database):
        """When existing OS contains 'DHCP' and the new one does not, DHCP OS is preserved."""
        tmp_db.upsert_host({
            "ip": "10.0.0.1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "os": "Windows 10/11 (DHCP)",
        })
        tmp_db.upsert_host({
            "ip": "10.0.0.1",
            "os": "Linux",
        })
        hosts, _ = tmp_db.get_hosts()
        assert "DHCP" in hosts[0]["os"]

    def test_upsert_host_missing_ip_noop(self, tmp_db: Database):
        """A host dict without an 'ip' key should be silently ignored."""
        tmp_db.upsert_host({"mac": "aa:bb:cc:dd:ee:ff"})
        hosts, total = tmp_db.get_hosts()
        assert hosts == []
        assert total == 0

    def test_get_hosts_ordered_by_last_seen(self, tmp_db: Database):
        """Hosts should be returned ordered by last_seen descending (most recent first)."""
        tmp_db.upsert_host({"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:aa"})
        time.sleep(0.05)
        tmp_db.upsert_host({"ip": "10.0.0.2", "mac": "bb:bb:bb:bb:bb:bb"})
        hosts, _ = tmp_db.get_hosts()
        assert hosts[0]["ip"] == "10.0.0.2"
        assert hosts[1]["ip"] == "10.0.0.1"

    def test_clear_hosts(self, tmp_db: Database, sample_host: dict):
        """clear_hosts() should remove all hosts."""
        tmp_db.upsert_host(sample_host)
        hosts, total = tmp_db.get_hosts()
        assert total == 1
        tmp_db.clear_hosts()
        hosts, total = tmp_db.get_hosts()
        assert hosts == []
        assert total == 0


class TestEvents:
    def test_log_event(self, tmp_db: Database):
        """Logged events should be retrievable with correct type and data."""
        tmp_db.log_event("arp_new", {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"})
        events, total = tmp_db.get_events()
        assert total == 1
        assert len(events) == 1
        assert events[0]["type"] == "arp_new"
        assert events[0]["data"]["ip"] == "10.0.0.1"
        assert "ts" in events[0]["data"]  # log_event adds a timestamp

    def test_get_events_limit_offset(self, tmp_db: Database):
        """get_events should respect limit and offset parameters."""
        for i in range(5):
            tmp_db.log_event("evt", {"seq": i})
            time.sleep(0.01)  # Ensure distinct timestamps

        # Events are DESC by timestamp, so most recent first.
        events, total = tmp_db.get_events(limit=2, offset=2)
        assert total == 5
        assert len(events) == 2

    def test_get_events_json_parsing(self, tmp_db: Database):
        """The data field should be parsed into a dict, not returned as a JSON string."""
        tmp_db.log_event("test", {"key": "value", "nested": {"a": 1}})
        events, _ = tmp_db.get_events()
        assert isinstance(events[0]["data"], dict)
        assert events[0]["data"]["key"] == "value"
        assert events[0]["data"]["nested"]["a"] == 1


class TestSearchAndSort:
    def test_search_by_ip(self, tmp_db: Database, sample_host: dict):
        """Searching by IP fragment should match hosts."""
        tmp_db.upsert_host(sample_host)
        tmp_db.upsert_host({"ip": "10.0.0.1", "mac": "11:22:33:44:55:66"})
        hosts, total = tmp_db.get_hosts(search="192.168")
        assert total == 1
        assert hosts[0]["ip"] == "192.168.1.100"

    def test_search_by_vendor(self, tmp_db: Database, sample_host: dict):
        """Searching by vendor name should match."""
        tmp_db.upsert_host(sample_host)
        hosts, total = tmp_db.get_hosts(search="TestVendor")
        assert total == 1

    def test_sort_by_ip_asc(self, tmp_db: Database):
        """Sorting by IP ascending should work."""
        tmp_db.upsert_host({"ip": "10.0.0.2", "mac": "bb:bb:bb:bb:bb:bb"})
        tmp_db.upsert_host({"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:aa"})
        hosts, _ = tmp_db.get_hosts(sort_by="ip", sort_order="ASC")
        assert hosts[0]["ip"] == "10.0.0.1"
        assert hosts[1]["ip"] == "10.0.0.2"

    def test_invalid_sort_fallback(self, tmp_db: Database, sample_host: dict):
        """Invalid sort_by should fall back to last_seen."""
        tmp_db.upsert_host(sample_host)
        hosts, total = tmp_db.get_hosts(sort_by="INVALID_COLUMN")
        assert total == 1  # Should not error

    def test_sort_order_validation(self, tmp_db: Database, sample_host: dict):
        """Invalid sort_order should fall back to DESC."""
        tmp_db.upsert_host(sample_host)
        hosts, total = tmp_db.get_hosts(sort_order="INVALID")
        assert total == 1  # Should not error


class TestClearEvents:
    def test_clear_events(self, tmp_db: Database):
        """clear_events() should remove all events."""
        tmp_db.log_event("test", {"key": "value"})
        tmp_db.log_event("test2", {"key": "value2"})
        events, total = tmp_db.get_events()
        assert total == 2
        tmp_db.clear_events()
        events, total = tmp_db.get_events()
        assert total == 0
        assert events == []


class TestEventTypeFilter:
    def test_filter_events_by_type(self, tmp_db: Database):
        """get_events with event_type should only return matching events."""
        tmp_db.log_event("arp_new", {"ip": "10.0.0.1"})
        tmp_db.log_event("arp_storm", {"count": 100})
        tmp_db.log_event("arp_new", {"ip": "10.0.0.2"})

        events, total = tmp_db.get_events(event_type="arp_new")
        assert total == 2
        assert all(e["type"] == "arp_new" for e in events)

        events, total = tmp_db.get_events(event_type="arp_storm")
        assert total == 1


class TestGetStats:
    def test_get_stats_empty(self, tmp_db: Database):
        """get_stats on empty DB should return zeros."""
        stats = tmp_db.get_stats()
        assert stats["hosts"] == 0
        assert stats["events"] == 0
        assert stats["event_types"] == 0

    def test_get_stats_with_data(self, tmp_db: Database, sample_host: dict):
        """get_stats should return correct counts."""
        tmp_db.upsert_host(sample_host)
        tmp_db.upsert_host({"ip": "10.0.0.1", "mac": "11:22:33:44:55:66"})
        tmp_db.log_event("arp_new", {"ip": "10.0.0.1"})
        tmp_db.log_event("arp_storm", {"count": 100})

        stats = tmp_db.get_stats()
        assert stats["hosts"] == 2
        assert stats["events"] == 2
        assert stats["event_types"] == 2


class TestRefreshStats:
    def test_update_refresh_stat_insert_and_average(self, tmp_db: Database):
        """First insert creates with samples=1; second call computes moving average."""
        tmp_db.update_refresh_stat("host_a", "host_b", 10.0)

        # Verify initial state
        conn = tmp_db.get_connection()
        row = conn.execute(
            "SELECT * FROM refresh_stats WHERE requester=? AND target=?",
            ("host_a", "host_b"),
        ).fetchone()
        conn.close()
        assert row["samples"] == 1
        assert row["avg_interval"] == pytest.approx(10.0)

        # Second update: moving average = (10 * 1 + 20) / 2 = 15
        tmp_db.update_refresh_stat("host_a", "host_b", 20.0)
        conn = tmp_db.get_connection()
        row = conn.execute(
            "SELECT * FROM refresh_stats WHERE requester=? AND target=?",
            ("host_a", "host_b"),
        ).fetchone()
        conn.close()
        assert row["samples"] == 2
        assert row["avg_interval"] == pytest.approx(15.0)
