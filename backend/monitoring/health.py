"""Configurable device health checks and state transitions."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from backend.models import Device
from .continuous import DeviceRegistry


@dataclass(frozen=True, slots=True)
class HealthSettings:
    health_check_interval: float = 30.0
    timeout: float = 1.0
    failure_threshold: int = 3
    warning_latency_threshold: float = 250.0

    def __post_init__(self) -> None:
        if self.health_check_interval <= 0 or self.timeout <= 0:
            raise ValueError("health intervals and timeout must be greater than zero")
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if self.warning_latency_threshold < 0:
            raise ValueError("warning_latency_threshold cannot be negative")


@dataclass(frozen=True, slots=True)
class HealthCheckResult:
    reachable: bool
    latency_ms: float | None


class HealthMonitor:
    """Evaluate one health result while retaining consecutive failures."""

    def __init__(self, settings: HealthSettings | None = None) -> None:
        self.settings = settings or HealthSettings()
        self.failures: dict[str, int] = {}

    def evaluate(self, device: Device, result: HealthCheckResult) -> str:
        if not result.reachable:
            failures = self.failures.get(device.ip, 0) + 1
            self.failures[device.ip] = failures
            device.latency_ms = None
            if failures >= self.settings.failure_threshold:
                return "OFFLINE"
            return "WARNING" if failures > 1 else "UNKNOWN"
        self.failures[device.ip] = 0
        device.latency_ms = result.latency_ms
        if result.latency_ms is None:
            return "UNKNOWN"
        if result.latency_ms >= self.settings.warning_latency_threshold:
            return "WARNING"
        return "ONLINE"


class HealthMonitoringService:
    """Periodically check registry devices without overlapping health runs."""

    def __init__(
        self,
        registry: DeviceRegistry,
        database: object,
        checker: Callable[[str, float], tuple[bool, float | None]],
        settings: HealthSettings | None = None,
        on_update: Callable[[Device], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_alert: Callable[[str, str, str, str | None], None] | None = None,
    ) -> None:
        self.registry = registry
        self.database = database
        self.checker = checker
        self.monitor = HealthMonitor(settings)
        self.on_update = on_update
        self.on_error = on_error
        self.on_alert = on_alert
        self._stop_event = threading.Event()
        self._run_lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def settings(self) -> HealthSettings:
        return self.monitor.settings

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        if self.running:
            return False
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="health-monitor")
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(0.0, timeout))

    def run_once(self) -> bool:
        if not self._run_lock.acquire(blocking=False):
            return False
        try:
            for device in list(self.registry.devices.values()):
                try:
                    reachable, latency = self.checker(device.ip, self.settings.timeout)
                    result = HealthCheckResult(bool(reachable), latency)
                    device.status = self.monitor.evaluate(device, result)
                    if self.on_alert is not None:
                        if device.status == "OFFLINE":
                            self.on_alert("DEVICE_OFFLINE", "HIGH", f"{device.ip} is offline", device.ip)
                        elif device.status == "WARNING" and result.latency_ms is not None:
                            self.on_alert("HIGH_LATENCY", "MEDIUM", f"{device.ip} latency is high", device.ip)
                        elif device.status == "ONLINE":
                            self.on_alert("DEVICE_ONLINE", "INFO", f"{device.ip} is online", device.ip)
                    if result.reachable:
                        device.last_seen = datetime.now(timezone.utc).isoformat(timespec="seconds")
                    self.database.record_health_sample(
                        device.ip,
                        device.status,
                        result.latency_ms,
                        result.reachable,
                        self.monitor.failures.get(device.ip, 0),
                    )
                    self.database.update_device_health(
                        device.ip, device.status, result.latency_ms, result.reachable
                    )
                    if self.on_update is not None:
                        self.on_update(device)
                except (OSError, TimeoutError, ValueError) as exc:
                    if self.on_error is not None:
                        self.on_error(f"{device.ip}: {exc}")
            return True
        finally:
            self._run_lock.release()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self.run_once()
            self._stop_event.wait(self.settings.health_check_interval)
