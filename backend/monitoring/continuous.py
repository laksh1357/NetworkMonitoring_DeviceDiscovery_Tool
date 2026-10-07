"""Periodic discovery and device-registry coordination."""

from __future__ import annotations

import ipaddress
import sqlite3
import threading
from dataclasses import dataclass
from typing import Any, Callable

from backend.models import Device


@dataclass(frozen=True, slots=True)
class DiscoveryTransitions:
    """Changes observed between two completed discovery cycles."""

    new: tuple[Device, ...] = ()
    existing: tuple[Device, ...] = ()
    disappeared: tuple[Device, ...] = ()
    returned: tuple[Device, ...] = ()


class DeviceRegistry:
    """In-memory registry that de-duplicates observations by IP."""

    def __init__(self) -> None:
        self.devices: dict[str, Device] = {}
        self._online_ips: set[str] = set()

    def apply(self, discovered: list[Device]) -> DiscoveryTransitions:
        unique: dict[str, Device] = {}
        for device in discovered:
            if device.ip:
                unique[device.ip] = device
        current_ips = set(unique)
        new: list[Device] = []
        existing: list[Device] = []
        returned: list[Device] = []
        for ip, device in unique.items():
            previous = self.devices.get(ip)
            if previous is None:
                new.append(device)
            elif ip not in self._online_ips:
                returned.append(device)
            else:
                existing.append(device)
            self.devices[ip] = device
        disappeared: list[Device] = []
        for ip in self._online_ips - current_ips:
            previous = self.devices[ip]
            previous.status = "Offline"
            previous.latency_ms = None
            disappeared.append(previous)
        self._online_ips = current_ips
        return DiscoveryTransitions(tuple(new), tuple(existing), tuple(disappeared), tuple(returned))


class ContinuousDiscoveryService:
    """Run the existing scanner on a safe, non-overlapping schedule."""

    def __init__(
        self,
        scanner: Any,
        database: Any,
        subnet_detector: Callable[[], ipaddress.IPv4Network],
        interval_seconds: float = 60.0,
        on_cycle: Callable[[list[Device], DiscoveryTransitions], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
        health_service: Any | None = None,
        registry: DeviceRegistry | None = None,
        on_transitions: Callable[[DiscoveryTransitions], None] | None = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be greater than zero")
        self.scanner = scanner
        self.database = database
        self.subnet_detector = subnet_detector
        self.interval_seconds = interval_seconds
        self.on_cycle = on_cycle
        self.on_error = on_error
        self.on_progress = on_progress
        self.health_service = health_service
        self.registry = registry or DeviceRegistry()
        self.on_transitions = on_transitions
        self._stop_event = threading.Event()
        self._cycle_lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        if self.running:
            return False
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="continuous-discovery")
        self._thread.start()
        if self.health_service is not None:
            self.health_service.start()
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        stop = getattr(self.scanner, "stop", None)
        if callable(stop):
            stop()
        if self.health_service is not None:
            self.health_service.stop(timeout=timeout)
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(0.0, timeout))

    def run_once(self) -> bool:
        """Run one cycle synchronously; return False when another cycle is active."""
        if not self._cycle_lock.acquire(blocking=False):
            return False
        try:
            subnet = self.subnet_detector()
            completed = threading.Event()
            result: list[Device] = []
            error: list[str] = []

            def on_complete(devices: list[Device]) -> None:
                result.extend(devices)
                completed.set()

            def on_error(message: str) -> None:
                error.append(str(message))
                completed.set()

            def on_stopped() -> None:
                error.append("discovery cycle stopped")
                completed.set()

            self.scanner.scan(
                subnet,
                self.on_progress or (lambda _done, _total: None),
                on_complete,
                on_error,
                on_stopped,
            )
            if not completed.wait(timeout=max(5.0, self.interval_seconds)):
                raise TimeoutError("discovery cycle timed out")
            if error:
                raise RuntimeError(error[0])
            transitions = self.registry.apply(result)
            self.database.record_scan(result, total_devices_online=len(result))
            if self.on_transitions is not None:
                self.on_transitions(transitions)
            if self.health_service is not None:
                self.health_service.run_once()
            if self.on_cycle is not None:
                self.on_cycle(result, transitions)
            return True
        except (OSError, RuntimeError, TimeoutError, ValueError, sqlite3.Error) as exc:
            if self.on_error is not None:
                self.on_error(str(exc))
            return False
        finally:
            self._cycle_lock.release()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self.run_once()
            self._stop_event.wait(self.interval_seconds)
