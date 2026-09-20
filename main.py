"""Compatibility layer for the legacy top-level entry point used by tests and scripts.

This project now organizes network logic under src/, but older tooling and the
project tests import the public surface from the repository root as `main`.
"""

from __future__ import annotations

from src.core.database import NetworkDatabase
from src.core.models import Device
from src.discovery.port_scanner import OpenPort, scan_ports
from src.discovery.scanner import (
    NetworkScanner,
    detect_local_subnet,
    has_admin_privileges,
    infer_device_type,
    normalize_mac,
    ping_host,
    resolve_hostname,
    resolve_mac_from_arp,
)
from src.discovery.vendor_lookup import lookup_vendor, normalize_mac_prefix
from src.utils.notifications import notify_new_device

__all__ = [
    "Device",
    "NetworkDatabase",
    "NetworkScanner",
    "OpenPort",
    "detect_local_subnet",
    "has_admin_privileges",
    "infer_device_type",
    "lookup_vendor",
    "normalize_mac",
    "normalize_mac_prefix",
    "notify_new_device",
    "ping_host",
    "resolve_hostname",
    "resolve_mac_from_arp",
    "scan_ports",
]


if __name__ == "__main__":
    from src.__main__ import run_server

    run_server()
