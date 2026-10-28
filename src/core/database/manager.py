"""SQLite persistence for discovered devices and scan history."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from collections.abc import Iterable
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from src.core.models.scan_jobs import ScanJobState, validate_scan_job_transition
from src.security.merkle import event_leaf_hash, merkle_frontier_root, merkle_root


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

                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id TEXT PRIMARY KEY,
                    state TEXT NOT NULL CHECK (state IN (
                        'NEW', 'VALIDATING', 'QUEUED', 'RUNNING', 'RETRY_PENDING',
                        'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT'
                    )),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
                    error_message TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_scan_jobs_state_updated
                    ON scan_jobs(state, updated_at DESC);

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

                CREATE TABLE IF NOT EXISTS device_identities (
                    id TEXT PRIMARY KEY,
                    identity_key TEXT NOT NULL UNIQUE,
                    current_state TEXT NOT NULL,
                    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
                    uncertainty REAL NOT NULL CHECK (uncertainty BETWEEN 0 AND 1),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS network_observations (
                    id TEXT PRIMARY KEY,
                    device_identity_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    fingerprint TEXT,
                    open_ports TEXT NOT NULL DEFAULT '[]',
                    latency_ms REAL,
                    packet_loss REAL,
                    source TEXT NOT NULL,
                    interface TEXT NOT NULL DEFAULT 'auto',
                    protocol_observations TEXT NOT NULL DEFAULT '{}',
                    evidence TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_identity_observations_time
                    ON network_observations(device_identity_id, observed_at DESC);

                CREATE TABLE IF NOT EXISTS identity_conflicts (
                    id TEXT PRIMARY KEY,
                    device_identity_id TEXT NOT NULL,
                    conflict_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    uncertainty REAL NOT NULL CHECK (uncertainty BETWEEN 0 AND 1),
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    created_at TEXT NOT NULL,
                    resolved_at TEXT
                );

                CREATE TABLE IF NOT EXISTS unresolved_behavior (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_identity_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    features TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    promotion_status TEXT NOT NULL DEFAULT 'QUARANTINED'
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    leaf_hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_checkpoints (
                    sequence INTEGER PRIMARY KEY,
                    root_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_merkle_frontier (
                    level INTEGER PRIMARY KEY,
                    node_hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    ip TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS user_profile (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    display_name TEXT NOT NULL,
                    role_title TEXT NOT NULL,
                    email TEXT NOT NULL,
                    avatar_initials TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'admin',
                    display_name TEXT NOT NULL DEFAULT 'Admin User',
                    email TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    last_login TEXT
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_token_expires
                    ON sessions(token, expires_at);
                """
            )
            self._connection.execute(
                """
                INSERT OR IGNORE INTO user_profile
                    (id, display_name, role_title, email, avatar_initials)
                VALUES (1, 'Local Admin', 'Administrator', '', 'LA')
                """
            )

            # Seed default admin if no users exist
            user_count = self._connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if user_count == 0:
                default_password = os.environ.get("ADMIN_DEFAULT_PASSWORD", "admin123")
                salt = secrets.token_hex(16)
                pwd_hash = hashlib.pbkdf2_hmac(
                    "sha256", default_password.encode("utf-8"), salt.encode("utf-8"), 100000
                ).hex()
                self._connection.execute(
                    """
                    INSERT INTO users (username, password_hash, salt, role, display_name, email, created_at)
                    VALUES ('admin', ?, ?, 'admin', 'Administrator', 'admin@network.local', ?)
                    """,
                    (pwd_hash, salt, self._timestamp()),
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
            for column, definition in (
                ("device_type", "TEXT NOT NULL DEFAULT 'Unknown'"),
                ("custom_name", "TEXT NOT NULL DEFAULT ''"),
                ("notes", "TEXT NOT NULL DEFAULT ''"),
                ("location", "TEXT NOT NULL DEFAULT 'Main Network'"),
            ):
                if column not in columns:
                    self._connection.execute(f"ALTER TABLE devices ADD COLUMN {column} {definition}")
            observation_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(network_observations)"
                ).fetchall()
            }
            if "interface" not in observation_columns:
                self._connection.execute(
                    "ALTER TABLE network_observations ADD COLUMN interface TEXT NOT NULL DEFAULT 'auto'"
                )
            if "protocol_observations" not in observation_columns:
                self._connection.execute(
                    "ALTER TABLE network_observations ADD COLUMN protocol_observations TEXT NOT NULL DEFAULT '{}'"
                )
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
            self._migrate_audit_merkle_frontier()

    def _migrate_audit_merkle_frontier(self) -> None:
        events = self._connection.execute(
            "SELECT sequence, leaf_hash FROM audit_events ORDER BY sequence"
        ).fetchall()
        frontier_rows = self._connection.execute(
            "SELECT level FROM audit_merkle_frontier"
        ).fetchall()
        if not events or frontier_rows:
            return

        frontier: dict[int, bytes] = {}
        for expected_sequence, event in enumerate(events, start=1):
            if event["sequence"] != expected_sequence:
                raise ValueError("Cannot rebuild the audit Merkle frontier from a non-contiguous log")
            node = bytes.fromhex(event["leaf_hash"])
            level = 0
            while level in frontier:
                node = hashlib.sha256(frontier.pop(level) + node).digest()
                level += 1
            frontier[level] = node
        merkle_frontier_root(frontier, len(events))
        self._connection.executemany(
            "INSERT INTO audit_merkle_frontier (level, node_hash) VALUES (?, ?)",
            [(level, node.hex()) for level, node in frontier.items()],
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
        device_type: str = "Unknown",
        custom_name: str = "",
        notes: str = "",
        location: str = "Main Network",
        **kwargs: Any,
    ) -> None:
        """Insert a device or update its current identity and last-seen time."""
        timestamp = seen_at or self._timestamp()
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO devices
                    (ip, mac, hostname, vendor, status, latency_ms, first_seen, last_seen,
                     device_type, custom_name, notes, location)
                VALUES (?, ?, ?, ?, 'Online', ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = CASE WHEN excluded.mac != 'Unknown' THEN excluded.mac ELSE devices.mac END,
                    hostname = CASE WHEN excluded.hostname != 'Unknown' THEN excluded.hostname ELSE devices.hostname END,
                    vendor = CASE WHEN excluded.vendor != 'Unknown' THEN excluded.vendor ELSE devices.vendor END,
                    status = 'Online',
                    latency_ms = excluded.latency_ms,
                    last_seen = excluded.last_seen,
                    device_type = CASE WHEN excluded.device_type != 'Unknown' THEN excluded.device_type ELSE devices.device_type END,
                    custom_name = CASE WHEN excluded.custom_name != '' THEN excluded.custom_name ELSE devices.custom_name END,
                    notes = CASE WHEN excluded.notes != '' THEN excluded.notes ELSE devices.notes END,
                    location = CASE WHEN excluded.location != 'Main Network' THEN excluded.location ELSE devices.location END
                """,
                (
                    ip, mac or "Unknown", hostname or "Unknown", vendor or "Unknown",
                    None, timestamp, timestamp, device_type or "Unknown",
                    custom_name or "", notes or "", location or "Main Network",
                ),
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
        if not ip:
            raise ValueError("ip is required")
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE devices SET
                    custom_name = ?, notes = ?,
                    device_type = COALESCE(?, device_type),
                    hostname = COALESCE(?, hostname),
                    vendor = COALESCE(?, vendor),
                    mac = COALESCE(?, mac),
                    location = COALESCE(?, location)
                WHERE ip = ?
                """,
                (custom_name, notes, device_type, hostname, vendor, mac, location, ip),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"device not found: {ip}")

    def delete_device(self, ip: str) -> None:
        if not ip:
            raise ValueError("ip is required")
        with self._lock, self._connection:
            cursor = self._connection.execute("DELETE FROM devices WHERE ip = ?", (ip,))
            if cursor.rowcount == 0:
                raise ValueError(f"device not found: {ip}")

    def insert_activity_log(
        self,
        user_name: str,
        action_type: str,
        description: str,
        ip: str = "",
    ) -> None:
        if not user_name or not action_type:
            raise ValueError("user_name and action_type are required")
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO activity_logs (user_name, action_type, description, ip, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_name, action_type, description, ip, self._timestamp()),
            )

    def fetch_activity_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT id, user_name, action_type, description, ip, created_at
                FROM activity_logs ORDER BY created_at DESC, id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_user_profile(self) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT display_name, role_title, email, avatar_initials
                FROM user_profile WHERE id = 1
                """
            ).fetchone()
        if row is None:
            raise RuntimeError("Local administrator profile is missing")
        return dict(row)

    def update_user_profile(
        self,
        display_name: str,
        role_title: str,
        email: str,
        avatar_initials: str,
    ) -> None:
        if not display_name.strip() or not role_title.strip():
            raise ValueError("display_name and role_title are required")
        with self._lock, self._connection:
            self._connection.execute(
                """
                UPDATE user_profile
                SET display_name = ?, role_title = ?, email = ?, avatar_initials = ?
                WHERE id = 1
                """,
                (display_name, role_title, email, avatar_initials),
            )

    def clear_database(self) -> None:
        """Clear network data while preserving the administrator and audit evidence."""
        tables = (
            "devices",
            "scan_logs",
            "scan_jobs",
            "port_observations",
            "port_states",
            "port_events",
            "alerts",
            "notification_deliveries",
            "health_history",
            "device_events",
            "device_identities",
            "network_observations",
            "identity_conflicts",
            "unresolved_behavior",
            "activity_logs",
        )
        with self._lock, self._connection:
            for table in tables:
                self._connection.execute(f"DELETE FROM {table}")

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

    def create_scan_job(
        self, job_id: str | None = None, created_at: str | None = None
    ) -> str:
        """Persist a new scan job and return its identifier."""
        identifier = job_id or str(uuid4())
        timestamp = created_at or self._timestamp()
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO scan_jobs
                    (id, state, created_at, updated_at, retry_count, error_message)
                VALUES (?, 'NEW', ?, ?, 0, NULL)
                """,
                (identifier, timestamp, timestamp),
            )
        return identifier

    def fetch_scan_job(self, job_id: str) -> dict[str, Any] | None:
        """Return one persisted scan job, or ``None`` when it does not exist."""
        if not job_id:
            raise ValueError("job_id is required")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM scan_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return dict(row) if row else None

    def fetch_scan_jobs(
        self, state: ScanJobState | str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Return persisted scan jobs, newest updates first."""
        if limit < 1:
            raise ValueError("limit must be at least 1")
        query = "SELECT * FROM scan_jobs"
        parameters: tuple[Any, ...] = ()
        if state is not None:
            query += " WHERE state = ?"
            parameters = (ScanJobState(state).value,)
        query += " ORDER BY updated_at DESC LIMIT ?"
        parameters += (limit,)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def update_scan_job_state(
        self,
        job_id: str,
        state: ScanJobState | str,
        *,
        error_message: str | None = None,
        retry_count: int | None = None,
        updated_at: str | None = None,
    ) -> dict[str, Any]:
        """Validate and persist a scan job state transition."""
        if not job_id:
            raise ValueError("job_id is required")
        target = ScanJobState(state)
        if retry_count is not None and retry_count < 0:
            raise ValueError("retry_count cannot be negative")
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT state FROM scan_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"scan job not found: {job_id}")
            validate_scan_job_transition(row["state"], target)
            self._connection.execute(
                """
                UPDATE scan_jobs
                SET state = ?, updated_at = ?, error_message = ?,
                    retry_count = COALESCE(?, retry_count)
                WHERE id = ?
                """,
                (
                    target.value,
                    updated_at or self._timestamp(),
                    error_message,
                    retry_count if retry_count is not None else (
                        1 if target is ScanJobState.RETRY_PENDING else None
                    ),
                    job_id,
                ),
            )
        result = self.fetch_scan_job(job_id)
        assert result is not None
        return result

    def get_scan_job(self, job_id: str) -> dict[str, Any] | None:
        """Alias for :meth:`fetch_scan_job` for callers using get semantics."""
        return self.fetch_scan_job(job_id)

    def transition_scan_job(
        self, job_id: str, state: ScanJobState | str, **kwargs: Any
    ) -> dict[str, Any]:
        """Alias for :meth:`update_scan_job_state`."""
        return self.update_scan_job_state(job_id, state, **kwargs)

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
        query = "SELECT * FROM devices ORDER BY last_seen DESC"
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

    def append_audit_event(
        self,
        actor: str,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append an event and persist the current SHA-256 Merkle root."""
        import json

        if not actor.strip() or not action.strip():
            raise ValueError("actor and action are required")
        timestamp = self._timestamp()
        details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._lock, self._connection:
            sequence = int(
                self._connection.execute(
                    "SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_events"
                ).fetchone()[0]
            )
            event = {
                "sequence": sequence,
                "occurred_at": timestamp,
                "actor": actor,
                "action": action,
                "details": json.loads(details_json),
            }
            leaf_hash = event_leaf_hash(event)
            self._connection.execute(
                """
                INSERT INTO audit_events
                    (sequence, occurred_at, actor, action, details_json, leaf_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (sequence, timestamp, actor, action, details_json, leaf_hash),
            )
            frontier = {
                row["level"]: bytes.fromhex(row["node_hash"])
                for row in self._connection.execute(
                    "SELECT level, node_hash FROM audit_merkle_frontier"
                ).fetchall()
            }
            node = bytes.fromhex(leaf_hash)
            level = 0
            while level in frontier:
                left = frontier.pop(level)
                self._connection.execute(
                    "DELETE FROM audit_merkle_frontier WHERE level = ?",
                    (level,),
                )
                node = hashlib.sha256(left + node).digest()
                level += 1
            frontier[level] = node
            self._connection.execute(
                """
                INSERT INTO audit_merkle_frontier (level, node_hash)
                VALUES (?, ?)
                """,
                (level, node.hex()),
            )
            root_hash = merkle_frontier_root(frontier, sequence)
            self._connection.execute(
                """
                INSERT INTO audit_checkpoints (sequence, root_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (sequence, root_hash, timestamp),
            )
        return {**event, "leaf_hash": leaf_hash, "merkle_root": root_hash}

    def fetch_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        import json

        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT sequence, occurred_at, actor, action, details_json, leaf_hash
                FROM audit_events ORDER BY sequence DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "sequence": row["sequence"],
                "occurred_at": row["occurred_at"],
                "actor": row["actor"],
                "action": row["action"],
                "details": json.loads(row["details_json"]),
                "leaf_hash": row["leaf_hash"],
            }
            for row in rows
        ]

    def verify_audit_log(self) -> dict[str, Any]:
        import json

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT sequence, occurred_at, actor, action, details_json, leaf_hash
                FROM audit_events ORDER BY sequence
                """
            ).fetchall()
            checkpoint = self._connection.execute(
                """
                SELECT sequence, root_hash FROM audit_checkpoints
                ORDER BY sequence DESC LIMIT 1
                """
            ).fetchone()
        leaves: list[str] = []
        valid = True
        for expected_sequence, row in enumerate(rows, start=1):
            event = {
                "sequence": row["sequence"],
                "occurred_at": row["occurred_at"],
                "actor": row["actor"],
                "action": row["action"],
                "details": json.loads(row["details_json"]),
            }
            leaf_hash = event_leaf_hash(event)
            leaves.append(leaf_hash)
            if row["sequence"] != expected_sequence or not hmac.compare_digest(leaf_hash, row["leaf_hash"]):
                valid = False
        root_hash = merkle_root(leaves)
        if rows:
            valid = bool(
                valid
                and checkpoint
                and checkpoint["sequence"] == len(rows)
                and hmac.compare_digest(root_hash, checkpoint["root_hash"])
            )
        elif checkpoint:
            valid = False
        return {
            "valid": valid,
            "event_count": len(rows),
            "merkle_root": root_hash,
            "checkpoint_sequence": checkpoint["sequence"] if checkpoint else None,
            "checked_at": self._timestamp(),
            "scope": "database-local integrity check; not externally anchored",
        }

    def save_identity(self, identity_id: str, identity_key: str, state: str,
                      confidence: float, created_at: str | None = None) -> None:
        """Persist an ECIV identity without changing legacy device records."""
        if not identity_id or not identity_key or not 0 <= confidence <= 1:
            raise ValueError("identity id/key and confidence between 0 and 1 are required")
        timestamp = self._timestamp()
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO device_identities
                    (id, identity_key, current_state, confidence, uncertainty, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    current_state = excluded.current_state,
                    confidence = excluded.confidence,
                    uncertainty = excluded.uncertainty,
                    updated_at = excluded.updated_at
                """,
                (identity_id, identity_key, state, confidence, 1.0 - confidence,
                 created_at or timestamp, timestamp),
            )

    def save_identity_observation(self, identity_id: str, observation: dict[str, Any]) -> None:
        """Persist a normalized observation as immutable ECIV evidence."""
        import json

        required = ("observation_id", "ip", "mac", "hostname", "vendor", "source")
        if not identity_id or any(key not in observation for key in required):
            raise ValueError("identity_id and required observation fields are needed")
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR IGNORE INTO network_observations
                    (id, device_identity_id, observed_at, ip, mac, hostname, vendor,
                     fingerprint, open_ports, latency_ms, packet_loss, source, interface,
                     protocol_observations, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation["observation_id"], identity_id,
                    observation.get("observed_at", self._timestamp()), observation["ip"],
                    observation["mac"], observation["hostname"], observation["vendor"],
                    observation.get("fingerprint"), json.dumps(observation.get("open_ports", [])),
                    observation.get("latency_ms"), observation.get("packet_loss"),
                    observation["source"], observation.get("interface", "auto"),
                    json.dumps(observation.get("protocol_observations", {})),
                    json.dumps(observation.get("raw_evidence", {})),
                ),
            )

    def identity_observation_exists(self, observation_id: str) -> bool:
        """Return whether an observation has already been durably processed."""
        if not observation_id:
            raise ValueError("observation_id is required")
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM network_observations WHERE id = ?",
                (observation_id,),
            ).fetchone()
        return row is not None

    def fetch_identity_observation_owner(self, observation_id: str) -> str | None:
        """Return the owning identity for one persisted observation."""
        if not observation_id:
            raise ValueError("observation_id is required")
        with self._lock:
            row = self._connection.execute(
                "SELECT device_identity_id FROM network_observations WHERE id = ?",
                (observation_id,),
            ).fetchone()
        return str(row["device_identity_id"]) if row else None

    def fetch_identity_observations(self, identity_id: str, limit: int = 100) -> list[dict[str, Any]]:
        if not identity_id or limit < 1:
            raise ValueError("identity_id and a positive limit are required")
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM network_observations WHERE device_identity_id = ? "
                "ORDER BY observed_at DESC LIMIT ?", (identity_id, limit)
            ).fetchall()
        return [dict(row) for row in rows]

    def save_identity_conflict(self, conflict: dict[str, Any]) -> None:
        """Persist an ECIV conflict and keep it open until explicitly resolved."""
        required = ("conflict_id", "identity_id", "conflict_type", "severity", "uncertainty_score", "reason")
        if any(key not in conflict for key in required):
            raise ValueError("conflict is missing required fields")
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR IGNORE INTO identity_conflicts
                    (id, device_identity_id, conflict_type, severity, uncertainty, reason,
                     status, created_at, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    conflict["conflict_id"], conflict["identity_id"], conflict["conflict_type"],
                    conflict["severity"], conflict["uncertainty_score"], conflict["reason"],
                    conflict.get("status", "OPEN"), conflict.get("created_at", self._timestamp()),
                    conflict.get("resolved_at"),
                ),
            )

    def fetch_identities(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM device_identities ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def fetch_identity(self, identity_id: str) -> dict[str, Any] | None:
        if not identity_id:
            raise ValueError("identity_id is required")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM device_identities WHERE id = ?", (identity_id,)
            ).fetchone()
        return dict(row) if row else None

    def fetch_identity_conflicts(self, identity_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        query = "SELECT * FROM identity_conflicts"
        parameters: tuple[Any, ...] = ()
        if identity_id:
            query += " WHERE device_identity_id = ?"
            parameters = (identity_id,)
        query += " ORDER BY created_at DESC LIMIT ?"
        parameters += (limit,)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def resolve_identity_conflict(self, conflict_id: str) -> None:
        if not conflict_id:
            raise ValueError("conflict_id is required")
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE identity_conflicts SET status = 'RESOLVED', resolved_at = ? WHERE id = ?",
                (self._timestamp(), conflict_id),
            )

    def update_device_meta(
        self,
        ip: str,
        custom_name: str = "",
        notes: str = "",
        dev_type: str | None = None,
        hostname: str | None = None,
        vendor: str | None = None,
        mac: str | None = None,
        location: str | None = None,
    ) -> None:
        if not ip:
            raise ValueError("ip is required")
        with self._lock, self._connection:
            updates = ["custom_name = ?", "notes = ?"]
            params: list[Any] = [custom_name, notes]
            if dev_type is not None:
                updates.append("device_type = ?")
                params.append(dev_type)
            if hostname is not None:
                updates.append("hostname = ?")
                params.append(hostname)
            if vendor is not None:
                updates.append("vendor = ?")
                params.append(vendor)
            if mac is not None:
                updates.append("mac = ?")
                params.append(mac)
            if location is not None:
                updates.append("location = ?")
                params.append(location)
            params.append(ip)
            self._connection.execute(
                f"UPDATE devices SET {', '.join(updates)} WHERE ip = ?",
                tuple(params),
            )

    def delete_device(self, ip: str) -> None:
        if not ip:
            raise ValueError("ip is required")
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM devices WHERE ip = ?", (ip,))
            self._connection.execute("DELETE FROM port_observations WHERE ip = ?", (ip,))
            self._connection.execute("DELETE FROM port_states WHERE ip = ?", (ip,))
            self._connection.execute("DELETE FROM health_history WHERE ip = ?", (ip,))
            self._connection.execute("DELETE FROM device_events WHERE ip = ?", (ip,))

    def insert_alert(
        self,
        severity: str,
        title: str,
        description: str,
        ip: str | None = None,
    ) -> dict[str, Any] | None:
        sev = severity.lower()
        if sev not in {"info", "warning", "critical"}:
            sev = "info"
        alert_type = title.upper().replace(" ", "_") if title else "SCAN_ALERT"
        return self.create_alert(alert_type=alert_type, severity=sev, message=description or title, ip=ip)

    def fetch_activity_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, user_name, action_type, description, ip, timestamp FROM activity_logs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def insert_activity_log(
        self,
        user_name: str,
        action_type: str,
        description: str,
        ip: str = "",
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO activity_logs (user_name, action_type, description, ip, timestamp) VALUES (?, ?, ?, ?, ?)",
                (user_name, action_type, description, ip, self._timestamp()),
            )

    def get_user_profile(self) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT display_name, role_title, email, avatar_initials, updated_at FROM user_profile WHERE id = 1"
            ).fetchone()
        if row:
            return dict(row)
        return {
            "display_name": "Admin User",
            "role_title": "Administrator",
            "email": "admin@network.local",
            "avatar_initials": "AU",
            "updated_at": self._timestamp(),
        }

    def update_user_profile(
        self,
        display_name: str,
        role_title: str,
        email: str,
        avatar_initials: str,
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO user_profile (id, display_name, role_title, email, avatar_initials, updated_at)
                VALUES (1, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    display_name = excluded.display_name,
                    role_title = excluded.role_title,
                    email = excluded.email,
                    avatar_initials = excluded.avatar_initials,
                    updated_at = excluded.updated_at
                """,
                (display_name, role_title, email, avatar_initials, self._timestamp()),
            )

    def clear_database(self) -> None:
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM devices")
            self._connection.execute("DELETE FROM scan_logs")
            self._connection.execute("DELETE FROM scan_jobs")
            self._connection.execute("DELETE FROM alerts")
            self._connection.execute("DELETE FROM port_observations")
            self._connection.execute("DELETE FROM port_states")
            self._connection.execute("DELETE FROM port_events")
            self._connection.execute("DELETE FROM health_history")
            self._connection.execute("DELETE FROM device_events")
            self._connection.execute("DELETE FROM network_observations")
            self._connection.execute("DELETE FROM identity_conflicts")
            self._connection.execute("DELETE FROM unresolved_behavior")
            self._connection.execute("DELETE FROM notification_deliveries")
            self._connection.execute("DELETE FROM activity_logs")

    @staticmethod
    def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
        """Compute PBKDF2 hash using SHA-256 and return (hash_hex, salt_hex)."""
        actual_salt = salt or secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), actual_salt.encode("utf-8"), 100000
        ).hex()
        return pwd_hash, actual_salt

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "operator",
        display_name: str = "",
        email: str = "",
    ) -> dict[str, Any]:
        """Register a new user account with a hashed password."""
        uname = username.strip().lower()
        if not uname:
            raise ValueError("username cannot be empty")
        if not password or len(password) < 4:
            raise ValueError("password must be at least 4 characters")
        if role not in {"admin", "operator", "viewer"}:
            role = "operator"

        pwd_hash, salt = self.hash_password(password)
        now = self._timestamp()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, display_name, email, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (uname, pwd_hash, salt, role, display_name or username, email, now),
            )
            user_id = cursor.lastrowid
        return {
            "id": user_id,
            "username": uname,
            "role": role,
            "display_name": display_name or username,
            "email": email,
            "created_at": now,
        }

    def authenticate_user(self, username: str, password: str) -> dict[str, Any] | None:
        """Verify username and password against stored PBKDF2 hash."""
        uname = username.strip().lower()
        with self._lock:
            row = self._connection.execute(
                "SELECT id, username, password_hash, salt, role, display_name, email FROM users WHERE username = ?",
                (uname,),
            ).fetchone()
        if not row:
            return None

        pwd_hash, _ = self.hash_password(password, row["salt"])
        if not hmac.compare_digest(row["password_hash"], pwd_hash):
            return None

        now = self._timestamp()
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE users SET last_login = ? WHERE id = ?", (now, row["id"])
            )

        return {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "display_name": row["display_name"],
            "email": row["email"],
            "last_login": now,
        }

    def create_session(self, user_id: int, duration_hours: int = 24) -> str:
        """Generate a cryptographically secure session token."""
        token = secrets.token_hex(32)
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(hours=duration_hours)
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO sessions (token, user_id, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    token,
                    user_id,
                    created_at.isoformat(timespec="seconds"),
                    expires_at.isoformat(timespec="seconds"),
                ),
            )
        return token

    def validate_session(self, token: str) -> dict[str, Any] | None:
        """Validate an active session token and return the associated user."""
        if not token:
            return None
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            row = self._connection.execute(
                """
                SELECT s.token, s.expires_at, u.id, u.username, u.role, u.display_name, u.email
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ?
                """,
                (token,),
            ).fetchone()

        if not row:
            return None

        if row["expires_at"] < now_iso:
            with self._lock, self._connection:
                self._connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
            return None

        return {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "display_name": row["display_name"],
            "email": row["email"],
        }

    def delete_session(self, token: str) -> None:
        """Invalidate a session on logout."""
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM sessions WHERE token = ?", (token,))

    def count_users(self) -> int:
        """Return the number of registered user accounts."""
        with self._lock:
            return int(self._connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def list_users(self) -> list[dict[str, Any]]:
        """Return all registered user accounts without password hashes or salts."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, username, role, display_name, email, created_at, last_login FROM users ORDER BY id ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def change_password(self, user_id: int, old_password: str, new_password: str) -> bool:
        """Verify old password and update with newly hashed password."""
        if not new_password or len(new_password) < 4:
            raise ValueError("new password must be at least 4 characters")
        with self._lock:
            row = self._connection.execute(
                "SELECT password_hash, salt FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if not row:
            return False

        old_hash, _ = self.hash_password(old_password, row["salt"])
        if not hmac.compare_digest(row["password_hash"], old_hash):
            return False

        new_hash, new_salt = self.hash_password(new_password)
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                (new_hash, new_salt, user_id),
            )
        return True

    def __enter__(self) -> "NetworkDatabase":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
