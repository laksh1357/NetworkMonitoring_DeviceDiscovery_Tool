"""Transport-neutral scan service boundary.

This service intentionally delegates to the existing scanner. It provides a
small seam for future schedulers and WebSocket publishers without changing the
current desktop workflow.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

from main import Device, NetworkScanner


class ScanService:
    """Start one compatible discovery scan."""

    def __init__(self, scanner: NetworkScanner | None = None) -> None:
        self.scanner = scanner or NetworkScanner()

    @property
    def running(self) -> bool:
        return self.scanner.running

    def start(
        self,
        subnet: ipaddress.IPv4Network,
        on_progress: Callable[[int, int], None],
        on_complete: Callable[[list[Device]], None],
        on_error: Callable[[str], None],
        on_stopped: Callable[[], None] | None = None,
    ) -> None:
        self.scanner.scan(subnet, on_progress, on_complete, on_error, on_stopped)

    def stop(self) -> None:
        self.scanner.stop()

