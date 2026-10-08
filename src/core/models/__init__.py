"""Device domain model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Device:
    """A discovered network device.

    This mirrors the existing public model and is intentionally free of UI or
    persistence concerns so it can be shared by future API clients.
    """

    ip: str
    mac: str = "Unknown"
    vendor: str = "Unknown"
    hostname: str = "Unknown"
    status: str = "Offline"
    latency_ms: float | None = None
    last_seen: str = "Never"

    def as_row(self) -> tuple[str, str, str, str, str, str, str]:
        latency = f"{self.latency_ms:.1f} ms" if self.latency_ms is not None else "-"
        return (self.ip, self.mac, self.vendor, self.hostname, self.status, latency, self.last_seen)

