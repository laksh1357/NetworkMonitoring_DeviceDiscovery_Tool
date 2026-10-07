"""Discovery primitive adapters.

The legacy implementations remain available from ``main`` for compatibility
with existing callers and tests.
"""

from main import detect_local_subnet, has_admin_privileges, normalize_mac, resolve_hostname

__all__ = ["detect_local_subnet", "has_admin_privileges", "normalize_mac", "resolve_hostname"]

