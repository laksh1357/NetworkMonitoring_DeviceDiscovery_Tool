"""In-memory state helpers used by future continuous monitoring."""

from __future__ import annotations

from collections.abc import Iterable

from backend.models import Device


def online_ips(devices: Iterable[Device]) -> set[str]:
    """Return the addresses currently reported as online."""

    return {device.ip for device in devices if device.status == "Online"}

