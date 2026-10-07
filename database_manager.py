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
                    status TEXT NOT NULL DEFAULT 'Unknown',
                    latency_ms REAL,
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

                CREATE TABLE IF NOT EXISTS port_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                    service TEXT NOT NULL DEFAULT 'Unknown service',
                    observed_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_port_observations_ip
                    ON port_observations(ip, observed_at DESC);

                CREATE TABLE IF NOT EXISTS port_states (
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                    protocol TEXT NOT NULL DEFAULT 'tcp',
                    service TEXT NOT NULL DEFAULT 'Unknown service',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_scan TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    PRIMARY KEY (ip, port, protocol)
                );

                CREATE INDEX IF NOT EXISTS idx_port_states_status
                    ON port_states(status, last_scan DESC);

                CREATE TABLE IF NOT EXISTS port_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    type TEXT NOT NULL DEFAULT 'SCAN_FAILURE',
                    title TEXT NOT NULL,
                    message TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'warning',
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    resolved_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_status
                    ON alerts(status, created_at DESC);

                CREATE TABLE IF NOT EXISTS notification_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER,
                    channel TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL DEFAULT '',
                    attempted_at TEXT NOT NULL,
                    error_message TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_notification_deliveries_alert
                    ON notification_deliveries(alert_id, attempted_at DESC);

                CREATE TABLE IF NOT EXISTS health_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reachable INTEGER NOT NULL CHECK (reachable IN (0, 1)),
                    latency_ms REAL,
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    observed_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_health_history_ip_time
                    ON health_history(ip, observed_at DESC);

                CREATE TABLE IF NOT EXISTS device_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_device_events_time_type
                    ON device_events(occurred_at DESC, event_type);
                """
            )
            columns = {
                row["name"]
                for row in self._connection.execute("PRAGMA table_info(devices)").fetchall()
            }
            if "status" not in columns:
                self._connection.execute(
                    "ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'Unknown'"
                )
            if "latency_ms" not in columns:
                self._connection.execute("ALTER TABLE devices ADD COLUMN latency_ms REAL")
            alert_columns = {
                row["name"]
                for row in self._connection.execute("PRAGMA table_info(alerts)").fetchall()
            }
            if "type" not in alert_columns:
                self._connection.execute(
                    "ALTER TABLE alerts ADD COLUMN type TEXT NOT NULL DEFAULT 'SCAN_FAILURE'"
                )
            if "acknowledged" not in alert_columns:
                self._connection.execute(
                    "ALTER TABLE alerts ADD COLUMN acknowledged INTEGER NOT NULL DEFAULT 0"
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
                INSERT INTO devices (ip, mac, hostname, vendor, status, latency_ms, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 'Online', ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = excluded.mac,
                    hostname = excluded.hostname,
                    vendor = excluded.vendor,
                    status = 'Online',
                    latency_ms = excluded.latency_ms,
                    last_seen = excluded.last_seen
                """,
                (ip, mac or "Unknown", hostname or "Unknown", vendor or "Unknown", None, timestamp, timestamp),
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
            previous = {
                row["ip"]: row["status"]
                for row in self._connection.execute("SELECT ip, status FROM devices").fetchall()
            }
            self._connection.execute("UPDATE devices SET status = 'Offline'")
            for device in device_list:
                self._connection.execute(
                    """
                    INSERT INTO devices (ip, mac, hostname, vendor, status, latency_ms, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, 'Online', ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac = excluded.mac,
                        hostname = excluded.hostname,
                        vendor = excluded.vendor,
                        status = 'Online',
                        latency_ms = excluded.latency_ms,
                        last_seen = excluded.last_seen
                    """,
                    (
                        device.ip,
                        device.mac or "Unknown",
                        device.hostname or "Unknown",
                        device.vendor or "Unknown",
                        getattr(device, "latency_ms", None),
                        timestamp,
                        timestamp,
                    ),
                )
            cursor = self._connection.execute(
                "INSERT INTO scan_logs (timestamp, total_devices_online) VALUES (?, ?)",
                (timestamp, online_total),
            )
            for device in device_list:
                event_type = "DEVICE_DISCOVERED" if device.ip not in previous else (
                    "DEVICE_ONLINE" if previous[device.ip] == "Offline" else "DEVICE_UPDATED"
                )
                self._connection.execute(
                    "INSERT INTO device_events (ip, event_type, occurred_at) VALUES (?, ?, ?)",
                    (device.ip, event_type, timestamp),
                )
            current_ips = {device.ip for device in device_list}
            for ip, status in previous.items():
                if status != "Offline" and ip not in current_ips:
                    self._connection.execute(
                        "INSERT INTO device_events (ip, event_type, occurred_at) VALUES (?, 'DEVICE_OFFLINE', ?)",
                        (ip, timestamp),
                    )
        return int(cursor.lastrowid)

    def fetch_history_analytics(
        self, since: str, bucket_minutes: int, limit: int = 300
    ) -> dict[str, list[dict[str, Any]]]:
        """Return bounded, database-aggregated historical dashboard series."""
        if not since or bucket_minutes < 1 or limit < 1:
            raise ValueError("since, bucket_minutes, and limit are required")
        bucket_seconds = bucket_minutes * 60
        bucket_expression = (
            f"datetime((CAST(strftime('%s', observed_at) AS INTEGER) / {bucket_seconds})"
            f" * {bucket_seconds}, 'unixepoch')"
        )
        with self._lock:
            scan_rows = self._connection.execute(
                """
                SELECT timestamp AS bucket, MAX(total_devices_online) AS devices
                FROM scan_logs WHERE timestamp >= ?
                GROUP BY timestamp ORDER BY timestamp LIMIT ?
                """,
                (since, limit),
            ).fetchall()
            health_rows = self._connection.execute(
                f"""
                SELECT {bucket_expression} AS bucket,
                    SUM(CASE WHEN status IN ('ONLINE', 'WARNING') THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN status = 'OFFLINE' THEN 1 ELSE 0 END) AS offline,
                    AVG(latency_ms) AS average_latency
                FROM health_history
                WHERE observed_at >= ?
                GROUP BY bucket ORDER BY bucket LIMIT ?
                """,
                (since, limit),
            ).fetchall()
            alert_rows = self._connection.execute(
                f"""
                SELECT datetime((CAST(strftime('%s', created_at) AS INTEGER) / {bucket_seconds})
                    * {bucket_seconds}, 'unixepoch') AS bucket, COUNT(*) AS count
                FROM alerts WHERE created_at >= ?
                GROUP BY bucket ORDER BY bucket LIMIT ?
                """,
                (since, limit),
            ).fetchall()
            port_rows = self._connection.execute(
                f"""
                SELECT datetime((CAST(strftime('%s', occurred_at) AS INTEGER) / {bucket_seconds})
                    * {bucket_seconds}, 'unixepoch') AS bucket, COUNT(*) AS count
                FROM port_events WHERE occurred_at >= ?
                GROUP BY bucket ORDER BY bucket LIMIT ?
                """,
                (since, limit),
            ).fetchall()
            device_rows = self._connection.execute(
                f"""
                SELECT datetime((CAST(strftime('%s', occurred_at) AS INTEGER) / {bucket_seconds})
                    * {bucket_seconds}, 'unixepoch') AS bucket,
                    event_type, COUNT(*) AS count
                FROM device_events WHERE occurred_at >= ?
                GROUP BY bucket, event_type ORDER BY bucket LIMIT ?
                """,
                (since, limit),
            ).fetchall()
            uptime_rows = self._connection.execute(
                """
                SELECT ip,
                    SUM(reachable) * 1.0 / COUNT(*) AS uptime_ratio,
                    AVG(latency_ms) AS average_latency,
                    COUNT(*) AS samples
                FROM health_history WHERE observed_at >= ?
                GROUP BY ip ORDER BY ip LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return {
            "devices": [dict(row) for row in scan_rows],
            "availability": [dict(row) for row in health_rows],
            "alerts": [dict(row) for row in alert_rows],
            "ports": [dict(row) for row in port_rows],
            "device_events": [dict(row) for row in device_rows],
            "uptime": [dict(row) for row in uptime_rows],
        }

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
        query = "SELECT ip, mac, hostname, vendor, status, latency_ms, first_seen, last_seen FROM devices ORDER BY last_seen DESC"
        parameters: tuple[int, ...] = ()
        if limit is not None:
            if limit < 1:
                raise ValueError("limit must be at least 1")
            query += " LIMIT ?"
            parameters = (limit,)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def record_port_observations(self, ip: str, ports: Iterable[Any], observed_at: str | None = None) -> None:
        """Persist the currently open ports for one device in one transaction."""
        if not ip:
            raise ValueError("ip must not be empty")
        timestamp = observed_at or self._timestamp()
        port_list = list(ports)
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM port_observations WHERE ip = ?", (ip,))
            self._connection.executemany(
                """
                INSERT INTO port_observations (ip, port, service, observed_at)
                VALUES (?, ?, ?, ?)
                """,
                [(ip, int(port.port), str(port.service), timestamp) for port in port_list],
            )
        self.record_port_scan(ip, port_list, observed_at=timestamp)

    def record_port_scan(
        self,
        ip: str,
        ports: Iterable[Any],
        protocol: str = "tcp",
        observed_at: str | None = None,
    ) -> list[dict[str, Any]]:
        """Persist current port state and return NEW_OPEN_PORT/PORT_CLOSED events."""
        if not ip or not protocol:
            raise ValueError("ip and protocol are required")
        timestamp = observed_at or self._timestamp()
        current = {int(port.port): str(port.service) for port in ports}
        events: list[dict[str, Any]] = []
        with self._lock, self._connection:
            rows = self._connection.execute(
                "SELECT port, service, status FROM port_states WHERE ip = ? AND protocol = ?",
                (ip, protocol),
            ).fetchall()
            previous = {int(row["port"]): row for row in rows}
            for port, service in current.items():
                old = previous.get(port)
                if old is None or old["status"] != "OPEN":
                    events.append({"event_type": "NEW_OPEN_PORT", "ip": ip, "port": port, "protocol": protocol, "service": service})
                    self._connection.execute(
                        """
                        INSERT INTO port_states
                            (ip, port, protocol, service, first_seen, last_seen, last_scan, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN')
                        ON CONFLICT(ip, port, protocol) DO UPDATE SET
                            service = excluded.service, last_seen = excluded.last_seen,
                            last_scan = excluded.last_scan, status = 'OPEN'
                        """,
                        (ip, port, protocol, service, timestamp, timestamp, timestamp),
                    )
                else:
                    self._connection.execute(
                        "UPDATE port_states SET service = ?, last_seen = ?, last_scan = ?, status = 'OPEN' WHERE ip = ? AND port = ? AND protocol = ?",
                        (service, timestamp, timestamp, ip, port, protocol),
                    )
            for port, old in previous.items():
                if old["status"] == "OPEN" and port not in current:
                    events.append({"event_type": "PORT_CLOSED", "ip": ip, "port": port, "protocol": protocol, "service": old["service"]})
                    self._connection.execute(
                        "UPDATE port_states SET last_scan = ?, status = 'CLOSED' WHERE ip = ? AND port = ? AND protocol = ?",
                        (timestamp, ip, port, protocol),
                    )
            self._connection.executemany(
                """
                INSERT INTO port_events (ip, port, protocol, service, event_type, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [(event["ip"], event["port"], event["protocol"], event["service"], event["event_type"], timestamp) for event in events],
            )
        return events

    def fetch_port_summary(self, ip: str | None = None) -> list[dict[str, Any]]:
        """Return current open-port state, optionally for one device."""
        query = """
            SELECT ip, port, protocol, service, first_seen, last_seen, last_scan, status
            FROM port_states WHERE status = 'OPEN'
        """
        parameters: tuple[str, ...] = ()
        if ip:
            query += " AND ip = ?"
            parameters = (ip,)
        query += " ORDER BY ip, port"
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def fetch_port_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._lock:
            rows = self._connection.execute(
                "SELECT ip, port, protocol, service, event_type, occurred_at FROM port_events ORDER BY occurred_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def fetch_device_events(self, ip: str, limit: int = 50) -> list[dict[str, Any]]:
        if not ip or limit < 1:
            raise ValueError("ip and a positive limit are required")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT ip, event_type, occurred_at
                FROM device_events
                WHERE ip = ?
                ORDER BY occurred_at DESC, id DESC
                LIMIT ?
                """,
                (ip, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def fetch_open_port_counts(self) -> dict[str, int]:
        """Return open-port totals for all devices with one grouped query."""
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT ip, COUNT(*) AS open_ports
                FROM port_states
                WHERE status = 'OPEN'
                GROUP BY ip
                """
            ).fetchall()
        return {str(row["ip"]): int(row["open_ports"]) for row in rows}

    def count_active_alerts(self) -> int:
        """Return the number of unresolved alerts."""
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) AS total FROM alerts WHERE status = 'active'"
            ).fetchone()
        return int(row["total"])

    def create_alert(
        self, alert_type: str, severity: str, message: str, ip: str | None = None
    ) -> dict[str, Any] | None:
        """Create one active incident unless the same type/device is active."""
        if not alert_type or not severity or not message:
            raise ValueError("alert type, severity, and message are required")
        with self._lock, self._connection:
            existing = self._connection.execute(
                """
                SELECT id, type, severity, ip AS device, message, created_at,
                       acknowledged, resolved_at
                FROM alerts
                WHERE type = ? AND ((ip = ?) OR (ip IS NULL AND ? IS NULL))
                  AND status = 'active'
                ORDER BY id DESC LIMIT 1
                """,
                (alert_type, ip, ip),
            ).fetchone()
            if existing is not None:
                return None
            timestamp = self._timestamp()
            cursor = self._connection.execute(
                """
                INSERT INTO alerts
                    (ip, type, title, message, severity, status, created_at, acknowledged)
                VALUES (?, ?, ?, ?, ?, 'active', ?, 0)
                """,
                (ip, alert_type, message, message, severity, timestamp),
            )
            row = self._connection.execute(
                """
                SELECT id, type, severity, ip AS device, message, created_at,
                       acknowledged, resolved_at
                FROM alerts WHERE id = ?
                """,
                (cursor.lastrowid,),
            ).fetchone()
        return dict(row) if row is not None else None

    def acknowledge_alert(self, alert_id: int) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ? AND status = 'active'",
                (alert_id,),
            )

    def resolve_alert(self, alert_id: int) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE alerts SET status = 'resolved', resolved_at = ? WHERE id = ? AND status = 'active'",
                (self._timestamp(), alert_id),
            )

    def fetch_alerts(self, status: str | None = "active", limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        query = """
            SELECT id, type, severity, ip AS device, message, created_at,
                   acknowledged, resolved_at
            FROM alerts
        """
        parameters: tuple[Any, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            parameters = (status,)
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        parameters += (limit,)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def record_notification(
        self,
        alert_id: int | None,
        channel: str,
        status: str,
        message: str = "",
        error_message: str | None = None,
    ) -> None:
        if not channel or not status:
            raise ValueError("channel and status are required")
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO notification_deliveries
                    (alert_id, channel, status, message, attempted_at, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (alert_id, channel, status, message, self._timestamp(), error_message),
            )

    def fetch_notification_deliveries(self, alert_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        query = """
            SELECT alert_id, channel, status, message, attempted_at, error_message
            FROM notification_deliveries
        """
        parameters: tuple[Any, ...] = ()
        if alert_id is not None:
            query += " WHERE alert_id = ?"
            parameters = (alert_id,)
        query += " ORDER BY attempted_at DESC, id DESC LIMIT ?"
        parameters += (limit,)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def update_device_health(
        self, ip: str, status: str, latency_ms: float | None, reachable: bool = False
    ) -> None:
        """Update the current health state without changing identity timestamps."""
        if not ip or not status:
            raise ValueError("ip and status are required")
        with self._lock, self._connection:
            if reachable:
                self._connection.execute(
                    "UPDATE devices SET status = ?, latency_ms = ?, last_seen = ? WHERE ip = ?",
                    (status, latency_ms, self._timestamp(), ip),
                )
            else:
                self._connection.execute(
                    "UPDATE devices SET status = ?, latency_ms = ? WHERE ip = ?",
                    (status, latency_ms, ip),
                )

    def record_health_sample(
        self,
        ip: str,
        status: str,
        latency_ms: float | None,
        reachable: bool,
        consecutive_failures: int,
        observed_at: str | None = None,
    ) -> None:
        """Store one health observation for historical analysis."""
        if not ip or consecutive_failures < 0:
            raise ValueError("ip and a non-negative failure count are required")
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO health_history
                    (ip, status, reachable, latency_ms, consecutive_failures, observed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    ip,
                    status,
                    int(reachable),
                    latency_ms,
                    consecutive_failures,
                    observed_at or self._timestamp(),
                ),
            )

    def fetch_health_history(self, ip: str, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent health observations for one device."""
        if not ip or limit < 1:
            raise ValueError("ip is required and limit must be at least 1")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT ip, status, reachable, latency_ms, consecutive_failures, observed_at
                FROM health_history
                WHERE ip = ?
                ORDER BY observed_at DESC, id DESC
                LIMIT ?
                """,
                (ip, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "NetworkDatabase":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
