"""Best-effort native desktop notifications."""

from __future__ import annotations

import platform
import subprocess
from importlib.util import find_spec

if platform.system() == "Darwin" and find_spec("pyobjus") is None:
    notification = None
else:
    try:
        from plyer import notification
    except ImportError:
        notification = None


def notify_new_device(ip: str, hostname: str = "Unknown") -> bool:
    """Show a native notification using Plyer, then an OS-native fallback."""
    label = hostname if hostname and hostname != "Unknown" else ip
    if notification is not None:
        try:
            notification.notify(
                title="New Device Detected",
                message=f"New Device Detected: {label}",
                app_name="LAN Watchtower",
                timeout=5,
            )
            return True
        except Exception:
            pass
    if platform.system() == "Darwin":
        escaped_label = label.replace("\\", "\\\\").replace('"', '\\"')
        script = f'display notification "New Device Detected: {escaped_label}" with title "LAN Watchtower"'
        try:
            subprocess.run(["osascript", "-e", script], capture_output=True, timeout=3, check=False)
            return True
        except (OSError, subprocess.SubprocessError):
            pass
    return False
