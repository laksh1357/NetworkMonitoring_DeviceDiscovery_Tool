"""Database-backed dashboard statistics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.core.database import NetworkDatabase


@dataclass(frozen=True, slots=True)
class DashboardStats:
    """A consistent snapshot used by dashboard consumers."""

    total_devices: int = 0
    online_devices: int = 0
    offline_devices: int = 0
    unknown_devices: int = 0
    active_alerts: int = 0
    open_ports: int = 0
    recently_discovered: list[dict[str, Any]] = field(default_factory=list)
    recently_offline: list[dict[str, Any]] = field(default_factory=list)
    recent_scans: list[dict[str, Any]] = field(default_factory=list)
    port_summary: list[dict[str, Any]] = field(default_factory=list)
    port_events: list[dict[str, Any]] = field(default_factory=list)
    active_alerts_list: list[dict[str, Any]] = field(default_factory=list)


class DashboardService:
    """Read dashboard data through bounded, batched database queries."""

    def __init__(self, database: NetworkDatabase) -> None:
        self.database = database

    def get_stats(self, recent_limit: int = 5, scan_limit: int = 10) -> DashboardStats:
        if recent_limit < 1 or scan_limit < 1:
            raise ValueError("dashboard limits must be at least 1")
        devices = self.database.fetch_devices()
        counts = {"Online": 0, "Offline": 0, "Unknown": 0}
        for device in devices:
            raw_status = str(device.get("status", "Unknown")).upper()
            status = {"ONLINE": "Online", "OFFLINE": "Offline", "WARNING": "Unknown"}.get(
                raw_status, "Unknown"
            )
            counts[status if status in counts else "Unknown"] += 1
        ports_by_ip = self.database.fetch_open_port_counts()
        recently_discovered = sorted(
            devices, key=lambda device: (device.get("first_seen", ""), device["ip"]), reverse=True
        )[:recent_limit]
        recently_offline = [
            device for device in devices if device.get("status", "Unknown") == "Offline"
        ][:recent_limit]
        return DashboardStats(
            total_devices=len(devices),
            online_devices=counts["Online"],
            offline_devices=counts["Offline"],
            unknown_devices=counts["Unknown"],
            active_alerts=self.database.count_active_alerts(),
            open_ports=sum(ports_by_ip.values()),
            recently_discovered=recently_discovered,
            recently_offline=recently_offline,
            recent_scans=self.database.fetch_scan_logs(scan_limit),
            port_summary=self.database.fetch_port_summary(),
            port_events=self.database.fetch_port_events(recent_limit),
            active_alerts_list=self.database.fetch_alerts(limit=recent_limit),
        )


def get_dashboard_stats(
    database: NetworkDatabase, recent_limit: int = 5, scan_limit: int = 10
) -> DashboardStats:
    """Convenience API for dashboard consumers that do not need a service object."""

    return DashboardService(database).get_stats(recent_limit=recent_limit, scan_limit=scan_limit)
