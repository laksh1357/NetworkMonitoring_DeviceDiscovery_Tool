"""Bounded historical network analytics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


TIME_RANGES = {
    "1h": (timedelta(hours=1), 5),
    "6h": (timedelta(hours=6), 15),
    "24h": (timedelta(hours=24), 60),
    "7d": (timedelta(days=7), 360),
    "30d": (timedelta(days=30), 1440),
}


class AnalyticsService:
    """Load only aggregated rows for a supported historical time range."""

    def __init__(self, database: Any) -> None:
        self.database = database

    def get_history(self, time_range: str = "24h") -> dict[str, list[dict[str, Any]]]:
        if time_range not in TIME_RANGES:
            raise ValueError(f"unsupported time range: {time_range}")
        duration, bucket_minutes = TIME_RANGES[time_range]
        since = (datetime.now(timezone.utc) - duration).isoformat(timespec="seconds")
        return self.database.fetch_history_analytics(since, bucket_minutes)

