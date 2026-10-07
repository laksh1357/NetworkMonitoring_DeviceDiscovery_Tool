"""Explainable rule-based detection of potentially suspicious activity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    device: str
    score: int
    level: str
    reasons: tuple[str, ...]

    @property
    def title(self) -> str:
        return "Potentially suspicious activity"


class AnomalyDetectionService:
    """Score observable signals without making maliciousness claims."""

    def __init__(
        self,
        unknown_vendor_points: int = 20,
        new_device_points: int = 25,
        unexpected_port_points: int = 10,
        multiple_port_change_points: int = 15,
        unusual_latency_points: int = 15,
        repeated_flapping_points: int = 15,
        suspicious_combination_points: int = 20,
        latency_threshold_ms: float = 250.0,
        repeated_event_threshold: int = 3,
        multiple_port_change_threshold: int = 3,
        unexpected_ports: frozenset[int] = frozenset({21, 22, 23, 139, 445, 3389, 5900}),
    ) -> None:
        if latency_threshold_ms < 0 or repeated_event_threshold < 2 or multiple_port_change_threshold < 2:
            raise ValueError("anomaly thresholds are invalid")
        self.unknown_vendor_points = unknown_vendor_points
        self.new_device_points = new_device_points
        self.unexpected_port_points = unexpected_port_points
        self.multiple_port_change_points = multiple_port_change_points
        self.unusual_latency_points = unusual_latency_points
        self.repeated_flapping_points = repeated_flapping_points
        self.suspicious_combination_points = suspicious_combination_points
        self.latency_threshold_ms = latency_threshold_ms
        self.repeated_event_threshold = repeated_event_threshold
        self.multiple_port_change_threshold = multiple_port_change_threshold
        self.unexpected_ports = unexpected_ports

    def assess(
        self,
        device: Any,
        open_ports: Iterable[Any] = (),
        port_events: Iterable[dict[str, Any]] = (),
        device_events: Iterable[dict[str, Any]] = (),
        health_samples: Iterable[dict[str, Any]] = (),
    ) -> RiskAssessment:
        reasons: list[str] = []
        score = 0
        vendor = str(getattr(device, "vendor", "") or "").strip().lower()
        if vendor in {"", "unknown", "unknown vendor"}:
            score += self.unknown_vendor_points
            reasons.append("Unknown vendor")

        event_rows = list(device_events)
        if any(str(row.get("event_type", "")).upper() == "DEVICE_DISCOVERED" for row in event_rows):
            score += self.new_device_points
            reasons.append("New device")

        ports = {self._port_number(port) for port in open_ports}
        unexpected = sorted(port for port in ports if port in self.unexpected_ports)
        if unexpected:
            score += min(self.unexpected_port_points * len(unexpected), 30)
            reasons.append("Unexpected open port(s): " + ", ".join(str(port) for port in unexpected))

        changes = list(port_events)
        if len(changes) >= self.multiple_port_change_threshold:
            score += self.multiple_port_change_points
            reasons.append(f"Multiple port changes ({len(changes)})")

        latency_values = [
            float(row["latency_ms"])
            for row in health_samples
            if row.get("latency_ms") is not None
        ]
        current_latency = getattr(device, "latency_ms", None)
        if current_latency is not None:
            latency_values.append(float(current_latency))
        if latency_values and max(latency_values) >= self.latency_threshold_ms:
            score += self.unusual_latency_points
            reasons.append(f"Unusual latency ({max(latency_values):.1f} ms)")

        flapping = sum(
            str(row.get("event_type", "")).upper() in {"DEVICE_OFFLINE", "DEVICE_ONLINE"}
            for row in event_rows
        )
        if flapping >= self.repeated_event_threshold:
            score += self.repeated_flapping_points
            reasons.append(f"Repeated appearance/disappearance ({flapping} events)")

        if self._has_suspicious_combination(ports):
            score += self.suspicious_combination_points
            reasons.append("Suspicious service/port combination")

        bounded_score = min(100, max(0, int(score)))
        level = (
            "CRITICAL" if bounded_score >= 81 else
            "HIGH" if bounded_score >= 61 else
            "MEDIUM" if bounded_score >= 31 else
            "LOW"
        )
        return RiskAssessment(str(getattr(device, "ip", "Unknown")), bounded_score, level, tuple(reasons))

    @staticmethod
    def _port_number(port: Any) -> int:
        if isinstance(port, dict):
            return int(port["port"])
        return int(getattr(port, "port", port))

    @staticmethod
    def _has_suspicious_combination(ports: set[int]) -> bool:
        return {22, 3389}.issubset(ports) or {23, 445}.issubset(ports) or {5432, 3389}.issubset(ports)
