"""Thread-safe event publication for live dashboard consumers."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any

from src.core.events import BackendEvent


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return _json_value(asdict(value))
    if hasattr(value, "as_row") and callable(value.as_row):
        return value.as_row()
    if hasattr(value, "__dict__"):
        return {
            key: _json_value(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    return value


def serialize_event(event: BackendEvent) -> str:
    """Serialize an event using the public WebSocket message contract."""
    return json.dumps(
        {
            "event": event.name,
            "timestamp": event.occurred_at.astimezone(timezone.utc).isoformat(),
            "data": _json_value(event.payload),
        },
        separators=(",", ":"),
        default=str,
    )


class EventHub:
    """Publish events to local UI and WebSocket subscribers."""

    def __init__(self) -> None:
        self._subscribers: set[Callable[[str], None]] = set()
        self._lock = threading.RLock()

    def subscribe(self, callback: Callable[[str], None]) -> Callable[[], None]:
        with self._lock:
            self._subscribers.add(callback)

        def unsubscribe() -> None:
            with self._lock:
                self._subscribers.discard(callback)

        return unsubscribe

    def publish(self, name: str, data: Any) -> str:
        message = serialize_event(BackendEvent.create(name, data))
        with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber(message)
            except (ConnectionError, OSError, RuntimeError):
                with self._lock:
                    self._subscribers.discard(subscriber)
        return message
