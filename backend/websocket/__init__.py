"""Live dashboard event hub and optional WebSocket endpoint."""

from .events import EventHub, serialize_event
from .server import WebSocketServer

__all__ = ["EventHub", "WebSocketServer", "serialize_event"]
