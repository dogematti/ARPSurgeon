from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

class Database:
    def __init__(self, db_path: str = "arpsurgeon.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Hosts table
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
        
        # Events table
        # Storing details as JSON for flexibility
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                type TEXT,
                data JSON
            )
        """)
        
        # Refresh Stats table (for topology)
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
        
        conn.commit()
        conn.close()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_hosts(self) -> list[dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM hosts ORDER BY last_seen DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_events(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset))
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for row in rows:
            d = dict(row)
            if d.get("data"):
                try:
                    d["data"] = json.loads(d["data"])
                except json.JSONDecodeError:
                    pass
            results.append(d)
        return results

    def upsert_host(self, host: dict[str, Any]) -> None:
        """
        Insert or update a host entry.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Prepare data
        ip = host.get("ip")
        if not ip:
            return

        now = time.time()
        
        # Check if exists
        cursor.execute("SELECT * FROM hosts WHERE ip = ?", (ip,))
        existing = cursor.fetchone()
        
        if existing:
            # Update
            new_count = existing["count"] + 1
            # Merge fields (prefer new non-empty values, else keep old)
            mac = host.get("mac") or existing["mac"]
            hostname = host.get("hostname") or existing["hostname"]
            vendor = host.get("vendor") or existing["vendor"]
            os_guess = host.get("os") or existing["os"]
            
            # Prioritize specific OS guess over "Unknown"
            if existing["os"] and "DHCP" in existing["os"] and "DHCP" not in str(os_guess):
                 os_guess = existing["os"]

            cursor.execute("""
                UPDATE hosts 
                SET mac = ?, hostname = ?, vendor = ?, os = ?, last_seen = ?, count = ?
                WHERE ip = ?
            """, (mac, hostname, vendor, os_guess, now, new_count, ip))
        else:
            # Insert
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
        conn.close()

    def log_event(self, event_type: str, data: dict[str, Any]) -> None:
        conn = self.get_connection()
        cursor = conn.cursor()
        now = time.time()
        data["ts"] = now # Ensure TS is in data too
        
        cursor.execute("""
            INSERT INTO events (timestamp, type, data)
            VALUES (?, ?, ?)
        """, (now, event_type, json.dumps(data)))
        
        conn.commit()
        conn.close()

    def update_refresh_stat(self, requester: str, target: str, interval: float) -> None:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM refresh_stats WHERE requester = ? AND target = ?", (requester, target))
        existing = cursor.fetchone()
        
        if existing:
            # Moving average calculation
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
        conn.close()

# Global DB instance (lazy init could be better but this is simple)
# We won't instantiate it here to avoid side effects on import.
