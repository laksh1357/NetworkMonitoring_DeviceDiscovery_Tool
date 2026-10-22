"""Validation helpers for network API request targets."""

from __future__ import annotations

import ipaddress


def parse_private_scan_subnet(value: object) -> ipaddress.IPv4Network:
    """Validate a bounded private IPv4 range before passing it to the scanner."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Subnet must be an IPv4 CIDR string")
    subnet = ipaddress.ip_network(value, strict=False)
    if not isinstance(subnet, ipaddress.IPv4Network):
        raise ValueError("Only private IPv4 subnets are supported")
    private_ranges = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    if not any(subnet.subnet_of(private_range) for private_range in private_ranges):
        raise ValueError("Scans are restricted to private IPv4 networks")
    if subnet.num_addresses > 1024:
        raise ValueError("Subnet is too large; scan a range with at most 1024 addresses")
    return subnet
