"""SQLite persistence for discovered devices and scan history."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class NetworkDatabase:
    """Thread-safe SQLite manager used by the network monitor."""

    def __init__(self, database_path: str | Path = "network_logs.db") -> None:
        self.database_path = Path(database_path)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    mac TEXT NOT NULL DEFAULT 'Unknown',
                    hostname TEXT NOT NULL DEFAULT 'Unknown',
                    vendor TEXT NOT NULL DEFAULT 'Unknown',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_devices_online INTEGER NOT NULL CHECK (total_devices_online >= 0)
                );

                CREATE INDEX IF NOT EXISTS idx_scan_logs_timestamp
                    ON scan_logs(timestamp DESC);
                """
            )

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def upsert_device(
        self,
        ip: str,
        mac: str = "Unknown",
        hostname: str = "Unknown",
        vendor: str = "Unknown",
        seen_at: str | None = None,
    ) -> None:
        """Insert a device or update its current identity and last-seen time."""
        timestamp = seen_at or self._timestamp()
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO devices (ip, mac, hostname, vendor, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = excluded.mac,
                    hostname = excluded.hostname,
                    vendor = excluded.vendor,
                    last_seen = excluded.last_seen
                """,
                (ip, mac or "Unknown", hostname or "Unknown", vendor or "Unknown", timestamp, timestamp),
            )

    def insert_scan_record(self, total_devices_online: int, timestamp: str | None = None) -> int:
        """Insert one scan session and return its database id."""
        if total_devices_online < 0:
            raise ValueError("total_devices_online cannot be negative")
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "INSERT INTO scan_logs (timestamp, total_devices_online) VALUES (?, ?)",
                (timestamp or self._timestamp(), total_devices_online),
            )
        return int(cursor.lastrowid)

    def record_scan(self, devices: Iterable[Any], total_devices_online: int | None = None) -> int:
        """Persist discovered devices and their scan total in one transaction."""
        timestamp = self._timestamp()
        device_list = list(devices)
        online_total = len(device_list) if total_devices_online is None else total_devices_online
        if online_total < 0:
            raise ValueError("total_devices_online cannot be negative")
        with self._lock, self._connection:
            for device in device_list:
                self._connection.execute(
                    """
                    INSERT INTO devices (ip, mac, hostname, vendor, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac = excluded.mac,
                        hostname = excluded.hostname,
                        vendor = excluded.vendor,
                        last_seen = excluded.last_seen
                    """,
                    (
                        device.ip,
                        device.mac or "Unknown",
                        device.hostname or "Unknown",
                        device.vendor or "Unknown",
                        timestamp,
                        timestamp,
                    ),
                )
            cursor = self._connection.execute(
                "INSERT INTO scan_logs (timestamp, total_devices_online) VALUES (?, ?)",
                (timestamp, online_total),
            )
        return int(cursor.lastrowid)

    def fetch_scan_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent scan sessions in newest-first order for the UI."""
        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT id, timestamp, total_devices_online
                FROM scan_logs
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def fetch_devices(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Return known devices ordered by most recently seen."""
        query = "SELECT ip, mac, hostname, vendor, first_seen, last_seen FROM devices ORDER BY last_seen DESC"
        parameters: tuple[int, ...] = ()
        if limit is not None:
            if limit < 1:
                raise ValueError("limit must be at least 1")
            query += " LIMIT ?"
            parameters = (limit,)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "NetworkDatabase":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
