"""Opt-in TCP connection decoys that record connection metadata only."""

from __future__ import annotations

import ipaddress
import socketserver
import threading
from collections.abc import Callable, Sequence
from typing import Any


class _DecoyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        callback = self.server.event_callback
        callback(
            {
                "source_ip": self.client_address[0],
                "source_port": self.client_address[1],
                "destination_ip": self.server.server_address[0],
                "destination_port": self.server.server_address[1],
            }
        )


class _ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        event_callback: Callable[[dict[str, Any]], None],
    ) -> None:
        self.event_callback = event_callback
        super().__init__(address, _DecoyHandler)


def validate_honeypot_config(enabled: bool, host: str, ports: Sequence[int]) -> None:
    if not enabled:
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Honeypot bind address must be a literal private or loopback IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address) or address.is_unspecified or address.is_multicast:
        raise ValueError("Honeypot must bind to a specific private or loopback IPv4 address")
    private_ranges = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    if not (address.is_loopback or any(address in network for network in private_ranges)):
        raise ValueError("Honeypot bind address must be private or loopback")
    if not ports or len(ports) > 16:
        raise ValueError("Configure between 1 and 16 honeypot ports")
    if len(set(ports)) != len(ports) or any(port < 1024 or port > 65535 for port in ports):
        raise ValueError("Honeypot ports must be unique values from 1024 through 65535")


class HoneypotListeners:
    """Start explicitly configured listeners; no commands or payloads are read."""

    def __init__(
        self,
        enabled: bool,
        host: str,
        ports: Sequence[int],
        event_callback: Callable[[dict[str, Any]], None],
    ) -> None:
        validate_honeypot_config(enabled, host, ports)
        self.enabled = enabled
        self.host = host
        self.ports = tuple(ports) if enabled else ()
        self.event_callback = event_callback
        self._servers: list[_ThreadedTCPServer] = []
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        if not self.enabled or self._servers:
            return
        try:
            for port in self.ports:
                server = _ThreadedTCPServer((self.host, port), self.event_callback)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                self._servers.append(server)
                self._threads.append(thread)
                thread.start()
        except OSError:
            self.stop()
            raise

    def stop(self) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)
        self._servers.clear()
        self._threads.clear()

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "running": bool(self._servers),
            "bind_address": self.host if self.enabled else None,
            "ports": list(self.ports) if self._servers else [],
            "mode": "connection metadata only; no payloads or commands are read",
        }
