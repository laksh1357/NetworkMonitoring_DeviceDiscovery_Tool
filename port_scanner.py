"""Fast, bounded TCP port scanning helpers."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable


COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP proxy/alternate HTTP",
}


@dataclass(frozen=True, slots=True)
class OpenPort:
    port: int
    service: str

    def as_text(self) -> str:
        return f"{self.port} ({self.service})"


def _check_port(ip: str, port: int, timeout: float) -> OpenPort | None:
    """Attempt one TCP connection; refused, timeout, and OS errors mean closed."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return OpenPort(port, COMMON_PORTS.get(port, "Unknown service"))
    except (ConnectionRefusedError, TimeoutError, socket.timeout, OSError):
        return None


def scan_ports(
    ip: str,
    ports: Iterable[int] = COMMON_PORTS,
    timeout: float = 0.35,
    max_workers: int = 32,
) -> list[OpenPort]:
    """Return open TCP ports for one host, ordered numerically.

    This scans only the supplied ports. It does not perform a full port scan.
    """
    if not ip:
        raise ValueError("ip must not be empty")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    requested_ports = sorted({int(port) for port in ports})
    if any(port < 1 or port > 65535 for port in requested_ports):
        raise ValueError("ports must be between 1 and 65535")
    if not requested_ports:
        return []

    workers = max(1, min(max_workers, len(requested_ports)))
    open_ports: list[OpenPort] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="port-scan") as executor:
        futures = [executor.submit(_check_port, ip, port, timeout) for port in requested_ports]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports, key=lambda item: item.port)
