from __future__ import annotations
from dataclasses import dataclass

@dataclass(slots=True)
class Device:
    ip: str
    mac: str = "Unknown"
    vendor: str = "Unknown"
    hostname: str = "Unknown"
    status: str = "Offline"
    latency_ms: float | None = None
    last_seen: str = "Never"
    device_type: str = "PC/Workstation"
    custom_name: str = ""
    notes: str = ""

    def as_row(self) -> tuple[str, str, str, str, str, str, str]:
        latency = f"{self.latency_ms:.1f} ms" if self.latency_ms is not None else "-"
        name_display = self.custom_name if self.custom_name else self.hostname
        return (self.ip, self.mac, self.vendor, name_display, self.status, latency, self.last_seen)
