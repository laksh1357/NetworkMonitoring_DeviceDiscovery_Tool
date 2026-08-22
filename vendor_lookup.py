"""Offline-first MAC address vendor lookup utilities."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


_OUI_PATH = Path(__file__).with_name("oui_vendors.json")
_MAC_HEX = re.compile(r"[^0-9A-Fa-f]")


def normalize_mac_prefix(mac: str) -> str:
    """Return the first three MAC octets as six uppercase hex characters."""
    compact = _MAC_HEX.sub("", mac or "")
    if len(compact) < 6 or not all(character in "0123456789abcdefABCDEF" for character in compact[:6]):
        return ""
    return compact[:6].upper()


def load_oui_database(path: Path = _OUI_PATH) -> dict[str, str]:
    """Load and normalize an OUI JSON file; a missing/bad file yields an empty map."""
    try:
        raw_data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        normalize_mac_prefix(prefix): str(vendor).strip()
        for prefix, vendor in raw_data.items()
        if normalize_mac_prefix(prefix) and str(vendor).strip()
    }


def _api_vendor_lookup(mac: str, timeout: float) -> str | None:
    """Optionally query macvendors.com when MAC_VENDOR_API is explicitly enabled."""
    if os.getenv("MAC_VENDOR_API", "").lower() not in {"1", "true", "yes"}:
        return None
    request = Request(
        f"https://api.macvendors.com/{mac}",
        headers={"User-Agent": "LAN-Watchtower/1.0"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            vendor = response.read().decode("utf-8").strip()
            return vendor or None
    except (OSError, URLError, UnicodeError):
        return None


def lookup_vendor(
    mac: str,
    database: dict[str, str] | None = None,
    allow_api: bool = False,
    api_timeout: float = 1.5,
) -> str:
    """Resolve a MAC vendor offline first, with optional graceful API fallback."""
    prefix = normalize_mac_prefix(mac)
    if not prefix:
        return "Unknown"
    vendors = database if database is not None else load_oui_database()
    vendor = vendors.get(prefix)
    if vendor:
        return vendor
    if allow_api:
        return _api_vendor_lookup(mac, api_timeout) or "Unknown"
    return "Unknown"
