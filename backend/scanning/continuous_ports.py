"""Bounded scheduled TCP port monitoring."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable

from backend.monitoring.continuous import DeviceRegistry


@dataclass(frozen=True, slots=True)
class PortMonitoringSettings:
    interval_seconds: float = 120.0
    timeout: float = 0.35
    max_workers: int = 16
    ports: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if self.interval_seconds <= 0 or self.timeout <= 0:
            raise ValueError("interval_seconds and timeout must be greater than zero")
        if self.max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        if any(port < 1 or port > 65535 for port in self.ports):
            raise ValueError("ports must be between 1 and 65535")


class ContinuousPortMonitoringService:
    """Run per-device port scans on a conservative schedule."""

    def __init__(
        self,
        registry: DeviceRegistry,
        database: Any,
        scanner: Callable[..., list[Any]],
        settings: PortMonitoringSettings | None = None,
        on_events: Callable[[list[dict[str, Any]]], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_alert: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.registry = registry
        self.database = database
        self.scanner = scanner
        self.settings = settings or PortMonitoringSettings()
        self.on_events = on_events
        self.on_error = on_error
        self.on_alert = on_alert
        self._stop_event = threading.Event()
        self._run_lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        if self.running:
            return False
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="port-monitor")
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(0.0, timeout))

    def scan_device(self, ip: str) -> list[Any]:
        """Scan one device and persist its port changes."""
        if not ip:
            raise ValueError("ip must not be empty")
        kwargs: dict[str, Any] = {
            "timeout": self.settings.timeout,
            "max_workers": self.settings.max_workers,
        }
        if self.settings.ports:
            kwargs["ports"] = self.settings.ports
        results = self.scanner(ip, **kwargs)
        events = self.database.record_port_scan(ip, results)
        if self.on_events is not None and events:
            self.on_events(events)
        if self.on_alert is not None:
            for event in events:
                self.on_alert(event)
        return results

    def run_once(self) -> bool:
        if not self._run_lock.acquire(blocking=False):
            return False
        try:
            for device in list(self.registry.devices.values()):
                if self._stop_event.is_set():
                    break
                if device.status.upper() not in {"ONLINE", "WARNING"}:
                    continue
                try:
                    self.scan_device(device.ip)
                except (OSError, TimeoutError, ValueError) as exc:
                    if self.on_error is not None:
                        self.on_error(f"{device.ip}: {exc}")
            return True
        finally:
            self._run_lock.release()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self.run_once()
            self._stop_event.wait(self.settings.interval_seconds)
