"""Real filesystem and host disk I/O measurements for the local service."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

import psutil


def _existing_path(path: Path) -> Path:
    candidate = path
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    if candidate.is_file():
        candidate = candidate.parent
    return candidate


def _directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        total = path.stat().st_size
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{path}{suffix}")
            if sidecar.exists():
                total += sidecar.stat().st_size
        return total
    total = 0
    for entry in path.rglob("*"):
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                continue
    return total


class StorageTelemetry:
    """Measure actual app-managed storage and cumulative host disk I/O rates."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        base_dir: str | Path,
        log_dir: str | Path | None = None,
        quarantine_dir: str | Path | None = None,
    ) -> None:
        self.database_path = Path(database_path)
        self.base_dir = Path(base_dir)
        self.log_dir = Path(log_dir or os.environ.get("LAN_WATCHTOWER_LOG_DIR", self.base_dir / "logs"))
        self.quarantine_dir = Path(
            quarantine_dir
            or os.environ.get("LAN_WATCHTOWER_QUARANTINE_DIR", self.base_dir / "quarantine")
        )
        self._lock = threading.Lock()
        self._previous_io: tuple[float, int, int] | None = None

    @staticmethod
    def _zone(zone_id: str, label: str, path: Path, *, filesystem: bool = False) -> dict[str, Any]:
        measured_path = _existing_path(path)
        usage = psutil.disk_usage(str(measured_path))
        zone_bytes = usage.used if filesystem else _directory_size(path)
        return {
            "id": zone_id,
            "label": label,
            "path": str(path),
            "used_bytes": zone_bytes,
            "volume_total_bytes": usage.total,
            "volume_free_bytes": usage.free,
            "volume_used_percent": usage.percent,
        }

    def _disk_io(self) -> dict[str, float | str]:
        counters = psutil.disk_io_counters()
        if counters is None:
            return {"status": "unavailable", "error": "Host disk I/O counters are unavailable"}
        now = time.monotonic()
        with self._lock:
            previous = self._previous_io
            self._previous_io = (now, counters.read_bytes, counters.write_bytes)
        if previous is None:
            return {"status": "sampling", "read_bytes_per_second": 0.0, "write_bytes_per_second": 0.0}
        elapsed = now - previous[0]
        if elapsed <= 0:
            return {"status": "sampling", "read_bytes_per_second": 0.0, "write_bytes_per_second": 0.0}
        return {
            "status": "available",
            "read_bytes_per_second": max(0.0, (counters.read_bytes - previous[1]) / elapsed),
            "write_bytes_per_second": max(0.0, (counters.write_bytes - previous[2]) / elapsed),
        }

    def snapshot(self) -> dict[str, Any]:
        system_drive = os.environ.get("SystemDrive")
        system_path = Path(f"{system_drive}\\") if system_drive else Path(Path.home().anchor)
        zones = [
            self._zone("system", "System volume", Path(system_path), filesystem=True),
            self._zone("database", "Network database", self.database_path),
            self._zone("logs", "Application logs", self.log_dir),
            self._zone("quarantine", "Quarantine evidence", self.quarantine_dir),
        ]
        return {"zones": zones, "host_disk_io": self._disk_io(), "sampled_at": time.time()}
