"""Notification channel boundaries."""

from .desktop import notify_new_device
from .providers import (
    EmailProvider,
    InAppProvider,
    NotificationDispatcher,
    NotificationMessage,
    WebhookProvider,
)

__all__ = [
    "notify_new_device",
    "EmailProvider",
    "InAppProvider",
    "NotificationDispatcher",
    "NotificationMessage",
    "WebhookProvider",
]
