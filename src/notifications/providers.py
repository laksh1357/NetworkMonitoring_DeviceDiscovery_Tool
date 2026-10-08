"""Notification providers and severity routing."""

from __future__ import annotations

import os
import json
import smtplib
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class NotificationMessage:
    title: str
    message: str
    severity: str
    alert_id: int | None = None


class NotificationProvider(Protocol):
    name: str

    def send(self, notification: NotificationMessage) -> None:
        ...


class InAppProvider:
    name = "dashboard"

    def __init__(self, database: Any) -> None:
        self.database = database

    def send(self, notification: NotificationMessage) -> None:
        self.database.record_notification(
            notification.alert_id, self.name, "delivered", notification.message
        )


class EmailProvider:
    name = "email"

    def __init__(self, environ: dict[str, str] | None = None) -> None:
        self.environ = environ or os.environ

    def send(self, notification: NotificationMessage) -> None:
        if self.environ.get("NOTIFICATION_EMAIL_ENABLED", "").lower() not in {"1", "true", "yes"}:
            raise RuntimeError("email notifications are disabled")
        host = self.environ.get("SMTP_HOST")
        username = self.environ.get("SMTP_USERNAME")
        password = self.environ.get("SMTP_PASSWORD")
        recipient = self.environ.get("NOTIFICATION_EMAIL_TO")
        if not host or not recipient:
            raise RuntimeError("SMTP_HOST and NOTIFICATION_EMAIL_TO are required")
        port = int(self.environ.get("SMTP_PORT", "587"))
        sender = self.environ.get("SMTP_FROM", username or "lan-watchtower@localhost")
        email = EmailMessage()
        email["Subject"] = f"[{notification.severity}] {notification.title}"
        email["From"] = sender
        email["To"] = recipient
        email.set_content(notification.message)
        with smtplib.SMTP(host, port, timeout=5) as smtp:
            smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(email)


class WebhookProvider:
    name = "webhook"

    def __init__(self, environ: dict[str, str] | None = None) -> None:
        self.environ = environ or os.environ

    def send(self, notification: NotificationMessage) -> None:
        url = self.environ.get("WEBHOOK_URL")
        if not url:
            raise RuntimeError("WEBHOOK_URL is required")
        payload = json.dumps(
            {
                "title": notification.title,
                "message": notification.message,
                "severity": notification.severity,
                "alert_id": notification.alert_id,
            }
        )
        request = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "LAN-Watchtower/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5):
            pass


class NotificationDispatcher:
    """Route notifications and isolate provider failures."""

    DEFAULT_CHANNELS = {
        "CRITICAL": ("dashboard", "email", "webhook"),
        "HIGH": ("dashboard", "email"),
        "MEDIUM": ("dashboard",),
        "LOW": ("dashboard",),
        "INFO": ("dashboard",),
    }

    def __init__(self, providers: list[NotificationProvider], channels: dict[str, tuple[str, ...]] | None = None) -> None:
        self.providers = {provider.name: provider for provider in providers}
        self.channels = channels or self.DEFAULT_CHANNELS

    def dispatch(self, notification: NotificationMessage) -> list[str]:
        delivered: list[str] = []
        for channel in self.channels.get(notification.severity, ("dashboard",)):
            provider = self.providers.get(channel)
            if provider is None:
                continue
            try:
                provider.send(notification)
            except Exception:
                continue
            delivered.append(channel)
        return delivered
