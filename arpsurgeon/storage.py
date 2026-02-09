from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Generator, Optional


class Database:
    def __init__(self, db_path: str = "arpsurgeon.db") -> None:
        self.db_path = db_path
        self._event_listeners: list = []
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    os TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    count INTEGER DEFAULT 1
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    type TEXT,
                    data JSON
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS refresh_stats (
                    requester TEXT,
                    target TEXT,
                    avg_interval REAL,
                    samples INTEGER,
                    last_updated REAL,
                    PRIMARY KEY (requester, target)
                )
            """)

            # Indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)")

            conn.commit()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # Keep for backward compat (tests use it directly)
    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def add_event_listener(self, callback) -> None:
        self._event_listeners.append(callback)

    def get_hosts(self, limit: int = 100, offset: int = 0,
                  search: str | None = None, sort_by: str = "last_seen",
                  sort_order: str = "DESC") -> tuple[list[dict[str, Any]], int]:
        with self._connect() as conn:
            cursor = conn.cursor()

            where_clause = ""
            params: list = []
            if search:
                where_clause = "WHERE ip LIKE ? OR mac LIKE ? OR hostname LIKE ? OR vendor LIKE ? OR os LIKE ?"
                pattern = f"%{search}%"
                params = [pattern] * 5

            cursor.execute(f"SELECT COUNT(*) FROM hosts {where_clause}", params)
            total = cursor.fetchone()[0]

            valid_sorts = {"ip", "mac", "hostname", "vendor", "os", "last_seen", "first_seen", "count"}
            if sort_by not in valid_sorts:
                sort_by = "last_seen"
            sort_order = "ASC" if sort_order.upper() == "ASC" else "DESC"

            cursor.execute(
                f"SELECT * FROM hosts {where_clause} ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?",
                params + [limit, offset]
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows], total

    def clear_hosts(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM hosts")
            conn.commit()

    def get_events(self, limit: int = 100, offset: int = 0,
                   event_type: str | None = None) -> tuple[list[dict[str, Any]], int]:
        with self._connect() as conn:
            cursor = conn.cursor()

            where_clause = ""
            params: list = []
            if event_type:
                where_clause = "WHERE type = ?"
                params = [event_type]

            cursor.execute(f"SELECT COUNT(*) FROM events {where_clause}", params)
            total = cursor.fetchone()[0]

            cursor.execute(
                f"SELECT * FROM events {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            )
            rows = cursor.fetchall()

        results = []
        for row in rows:
            d = dict(row)
            if d.get("data"):
                try:
                    d["data"] = json.loads(d["data"])
                except json.JSONDecodeError:
                    pass
            results.append(d)
        return results, total

    def clear_events(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM events")
            conn.commit()

    def upsert_host(self, host: dict[str, Any]) -> None:
        ip = host.get("ip")
        if not ip:
            return

        now = time.time()

        with self._connect() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM hosts WHERE ip = ?", (ip,))
            existing = cursor.fetchone()

            if existing:
                new_count = existing["count"] + 1
                mac = host.get("mac") or existing["mac"]
                hostname = host.get("hostname") or existing["hostname"]
                vendor = host.get("vendor") or existing["vendor"]
                os_guess = host.get("os") or existing["os"]

                if existing["os"] and "DHCP" in existing["os"] and "DHCP" not in str(os_guess):
                     os_guess = existing["os"]

                cursor.execute("""
                    UPDATE hosts
                    SET mac = ?, hostname = ?, vendor = ?, os = ?, last_seen = ?, count = ?
                    WHERE ip = ?
                """, (mac, hostname, vendor, os_guess, now, new_count, ip))
            else:
                cursor.execute("""
                    INSERT INTO hosts (ip, mac, hostname, vendor, os, first_seen, last_seen, count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip,
                    host.get("mac", "unknown"),
                    host.get("hostname", ""),
                    host.get("vendor", ""),
                    host.get("os", "unknown"),
                    host.get("first_seen", now),
                    now,
                    1
                ))

            conn.commit()

    def log_event(self, event_type: str, data: dict[str, Any]) -> None:
        now = time.time()
        data["ts"] = now

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO events (timestamp, type, data)
                VALUES (?, ?, ?)
            """, (now, event_type, json.dumps(data)))
            conn.commit()

        for listener in self._event_listeners:
            try:
                listener({"type": event_type, "data": data, "timestamp": now})
            except Exception:
                pass

    def update_refresh_stat(self, requester: str, target: str, interval: float) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM refresh_stats WHERE requester = ? AND target = ?", (requester, target))
            existing = cursor.fetchone()

            if existing:
                n = existing["samples"]
                old_avg = existing["avg_interval"]
                new_avg = (old_avg * n + interval) / (n + 1)

                cursor.execute("""
                    UPDATE refresh_stats
                    SET avg_interval = ?, samples = ?, last_updated = ?
                    WHERE requester = ? AND target = ?
                """, (new_avg, n + 1, time.time(), requester, target))
            else:
                cursor.execute("""
                    INSERT INTO refresh_stats (requester, target, avg_interval, samples, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                """, (requester, target, interval, 1, time.time()))

            conn.commit()

    def get_refresh_stats(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM refresh_stats ORDER BY last_updated DESC")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM hosts")
            host_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM events")
            event_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(DISTINCT type) FROM events")
            event_types = cursor.fetchone()[0]
            return {
                "hosts": host_count,
                "events": event_count,
                "event_types": event_types,
            }
