"""Typed events shared by monitoring transports and application services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class BackendEvent:
    """A transport-neutral event for future real-time consumers."""

    name: str
    payload: Any
    occurred_at: datetime

    @classmethod
    def create(cls, name: str, payload: Any) -> "BackendEvent":
        if not name:
            raise ValueError("event name must not be empty")
        return cls(name=name, payload=payload, occurred_at=datetime.now(timezone.utc))

