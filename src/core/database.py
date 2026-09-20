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
                    device_type TEXT NOT NULL DEFAULT 'PC/Workstation',
                    custom_name TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_devices_online INTEGER NOT NULL CHECK (total_devices_online >= 0)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'WARNING', 'INFO', 'RESOLVED')),
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    ip TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user_name TEXT NOT NULL DEFAULT 'Admin User',
                    action_type TEXT NOT NULL DEFAULT 'USER_ACTION',
                    description TEXT NOT NULL,
                    ip TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS user_profile (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    display_name TEXT NOT NULL DEFAULT 'Admin User',
                    role_title TEXT NOT NULL DEFAULT 'Administrator',
                    email TEXT NOT NULL DEFAULT 'admin@network.local',
                    avatar_initials TEXT NOT NULL DEFAULT 'AU'
                );

                CREATE INDEX IF NOT EXISTS idx_scan_logs_timestamp
                    ON scan_logs(timestamp DESC);

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                    ON alerts(timestamp DESC);

                CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp
                    ON activity_logs(timestamp DESC);
                """
            )
            # Lightweight Schema Migrations for existing databases
            for column, col_type in [
                ("device_type", "TEXT NOT NULL DEFAULT 'PC/Workstation'"),
                ("custom_name", "TEXT NOT NULL DEFAULT ''"),
                ("notes", "TEXT NOT NULL DEFAULT ''"),
                ("location", "TEXT NOT NULL DEFAULT 'Main Network'"),
            ]:
                try:
                    self._connection.execute(f"ALTER TABLE devices ADD COLUMN {column} {col_type}")
                except sqlite3.OperationalError:
                    pass  # Column already exists

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
        device_type: str = "PC/Workstation",
        custom_name: str = "",
        notes: str = "",
        location: str = "Main Network",
    ) -> None:
        """Insert a device or update its current identity and last-seen time."""
        timestamp = seen_at or self._timestamp()
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO devices (ip, mac, hostname, vendor, device_type, custom_name, notes, location, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = CASE WHEN excluded.mac != 'Unknown' THEN excluded.mac ELSE devices.mac END,
                    hostname = CASE WHEN excluded.hostname != 'Unknown' THEN excluded.hostname ELSE devices.hostname END,
                    vendor = CASE WHEN excluded.vendor != 'Unknown' THEN excluded.vendor ELSE devices.vendor END,
                    device_type = CASE WHEN excluded.device_type != 'PC/Workstation' THEN excluded.device_type ELSE devices.device_type END,
                    custom_name = CASE WHEN excluded.custom_name != '' THEN excluded.custom_name ELSE devices.custom_name END,
                    notes = CASE WHEN excluded.notes != '' THEN excluded.notes ELSE devices.notes END,
                    location = CASE WHEN excluded.location != 'Main Network' THEN excluded.location ELSE devices.location END,
                    last_seen = excluded.last_seen
                """,
                (ip, mac or "Unknown", hostname or "Unknown", vendor or "Unknown", device_type or "PC/Workstation", custom_name, notes, location or "Main Network", timestamp, timestamp),
            )

    def update_device_meta(
        self,
        ip: str,
        custom_name: str = "",
        notes: str = "",
        device_type: str | None = None,
        hostname: str | None = None,
        vendor: str | None = None,
        mac: str | None = None,
        location: str | None = None,
    ) -> None:
        """Fully update user-edited device properties."""
        with self._lock, self._connection:
            fields = []
            values = []
            if custom_name is not None:
                fields.append("custom_name = ?")
                values.append(custom_name)
            if notes is not None:
                fields.append("notes = ?")
                values.append(notes)
            if device_type:
                fields.append("device_type = ?")
                values.append(device_type)
            if hostname:
                fields.append("hostname = ?")
                values.append(hostname)
            if vendor:
                fields.append("vendor = ?")
                values.append(vendor)
            if mac:
                fields.append("mac = ?")
                values.append(mac)
            if location:
                fields.append("location = ?")
                values.append(location)

            if fields:
                values.append(ip)
                query = f"UPDATE devices SET {', '.join(fields)} WHERE ip = ?"
                self._connection.execute(query, tuple(values))

    def delete_device(self, ip: str) -> None:
        """Remove a device from the database."""
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM devices WHERE ip = ?", (ip,))

    def insert_alert(self, severity: str, title: str, message: str, ip: str = "") -> int:
        """Insert a new alert into the database log."""
        timestamp = self._timestamp()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "INSERT INTO alerts (timestamp, severity, title, message, ip) VALUES (?, ?, ?, ?, ?)",
                (timestamp, severity.upper(), title, message, ip),
            )
        return int(cursor.lastrowid)

    def fetch_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent alerts in newest-first order."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, timestamp, severity, title, message, ip FROM alerts ORDER BY timestamp DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def insert_activity_log(self, user_name: str, action_type: str, description: str, ip: str = "") -> int:
        """Insert a user action or system event into the activity audit trail."""
        timestamp = self._timestamp()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "INSERT INTO activity_logs (timestamp, user_name, action_type, description, ip) VALUES (?, ?, ?, ?, ?)",
                (timestamp, user_name or "Admin User", action_type, description, ip),
            )
        return int(cursor.lastrowid)

    def fetch_activity_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent activity audit trail logs."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, timestamp, user_name, action_type, description, ip FROM activity_logs ORDER BY timestamp DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_user_profile(self) -> dict[str, str]:
        """Fetch stored user profile metadata."""
        with self._lock:
            row = self._connection.execute("SELECT display_name, role_title, email, avatar_initials FROM user_profile WHERE id = 1").fetchone()
        if row:
            return dict(row)
        return {
            "display_name": "Admin User",
            "role_title": "Administrator",
            "email": "admin@network.local",
            "avatar_initials": "AU",
        }

    def update_user_profile(self, display_name: str, role_title: str, email: str, avatar_initials: str) -> None:
        """Update or insert stored user profile."""
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO user_profile (id, display_name, role_title, email, avatar_initials)
                VALUES (1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    display_name = excluded.display_name,
                    role_title = excluded.role_title,
                    email = excluded.email,
                    avatar_initials = excluded.avatar_initials
                """,
                (display_name, role_title, email, avatar_initials),
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
        device_data = [
            (
                device.ip,
                device.mac or "Unknown",
                device.hostname or "Unknown",
                device.vendor or "Unknown",
                getattr(device, "device_type", "PC/Workstation"),
                getattr(device, "custom_name", ""),
                getattr(device, "notes", ""),
                timestamp,
                timestamp,
            )
            for device in device_list
        ]

        with self._lock, self._connection:
            if device_data:
                self._connection.executemany(
                    """
                    INSERT INTO devices (ip, mac, hostname, vendor, device_type, custom_name, notes, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac = CASE WHEN excluded.mac != 'Unknown' THEN excluded.mac ELSE devices.mac END,
                        hostname = CASE WHEN excluded.hostname != 'Unknown' THEN excluded.hostname ELSE devices.hostname END,
                        vendor = CASE WHEN excluded.vendor != 'Unknown' THEN excluded.vendor ELSE devices.vendor END,
                        device_type = CASE WHEN excluded.device_type != 'PC/Workstation' THEN excluded.device_type ELSE devices.device_type END,
                        last_seen = excluded.last_seen
                    """,
                    device_data,
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
        query = "SELECT ip, mac, hostname, vendor, device_type, custom_name, notes, location, first_seen, last_seen FROM devices ORDER BY last_seen DESC"
        parameters: tuple[int, ...] = ()
        if limit is not None:
            if limit < 1:
                raise ValueError("limit must be at least 1")
            query += " LIMIT ?"
            parameters = (limit,)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def clear_database(self) -> None:
        """Clear all stored devices, scan history, and alert logs."""
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM devices")
            self._connection.execute("DELETE FROM scan_logs")
            self._connection.execute("DELETE FROM alerts")

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "NetworkDatabase":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
