"""Alert lifecycle and deduplication service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from src.notifications import NotificationDispatcher, NotificationMessage


ALERT_TYPES = {
    "NEW_DEVICE",
    "DEVICE_OFFLINE",
    "DEVICE_ONLINE",
    "HIGH_LATENCY",
    "NEW_OPEN_PORT",
    "PORT_CLOSED",
    "UNKNOWN_DEVICE",
    "SCAN_FAILURE",
}
SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


@dataclass(frozen=True, slots=True)
class Alert:
    id: int
    type: str
    severity: str
    device: str | None
    message: str
    created_at: str
    acknowledged: bool
    resolved_at: str | None


class AlertService:
    """Create and manage alerts without repeating active incidents."""

    def __init__(
        self,
        database: Any,
        dispatcher: NotificationDispatcher | None = None,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.database = database
        self.dispatcher = dispatcher
        self.on_event = on_event

    def create(
        self,
        alert_type: str,
        severity: str,
        message: str,
        device: str | None = None,
    ) -> dict[str, Any] | None:
        if alert_type not in ALERT_TYPES:
            raise ValueError(f"unsupported alert type: {alert_type}")
        if severity not in SEVERITIES:
            raise ValueError(f"unsupported severity: {severity}")
        alert = self.database.create_alert(alert_type, severity, message, device)
        if alert is not None and self.dispatcher is not None:
            self.dispatcher.dispatch(
                NotificationMessage(
                    title=alert_type.replace("_", " ").title(),
                    message=message,
                    severity=severity,
                    alert_id=int(alert["id"]),
                )
            )
        if alert is not None and self.on_event is not None:
            self.on_event("ALERT_CREATED", alert)
        return alert

    def acknowledge(self, alert_id: int) -> None:
        self.database.acknowledge_alert(alert_id)

    def resolve(self, alert_id: int) -> None:
        self.database.resolve_alert(alert_id)
        if self.on_event is not None:
            self.on_event("ALERT_RESOLVED", {"id": alert_id})

    def active(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.database.fetch_alerts(status="active", limit=limit)

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.database.fetch_alerts(status=None, limit=limit)
