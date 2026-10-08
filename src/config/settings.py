"""Validated runtime settings for the desktop monitoring application."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    network_interface: str = "auto"
    discovery_interval: float = 60.0
    health_check_interval: float = 30.0
    port_scan_interval: float = 120.0
    port_list: tuple[int, ...] = ()
    timeout: float = 1.0
    concurrency: int = 16
    offline_threshold: int = 3
    latency_threshold: float = 250.0

    def __post_init__(self) -> None:
        if not self.network_interface.strip():
            raise ValueError("network interface is required")
        if any(value <= 0 for value in (self.discovery_interval, self.health_check_interval, self.port_scan_interval, self.timeout)):
            raise ValueError("intervals and timeout must be greater than zero")
        if self.concurrency < 1 or self.offline_threshold < 1:
            raise ValueError("concurrency and offline threshold must be at least 1")
        if self.latency_threshold < 0:
            raise ValueError("latency threshold cannot be negative")
        if any(port < 1 or port > 65535 for port in self.port_list):
            raise ValueError("ports must be between 1 and 65535")

