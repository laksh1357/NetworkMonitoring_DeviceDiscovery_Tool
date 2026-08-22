"""Best-effort native desktop notifications."""

from __future__ import annotations

try:
    from plyer import notification
except ImportError:
    notification = None


def notify_new_device(ip: str, hostname: str = "Unknown") -> bool:
    """Show a native notification, returning False when the notifier is unavailable."""
    if notification is None:
        return False
    label = hostname if hostname and hostname != "Unknown" else ip
    try:
        notification.notify(
            title="New Device Detected",
            message=f"New Device Detected: {label}",
            app_name="LAN Watchtower",
            timeout=5,
        )
    except Exception:
        return False
    return True
