"""Explainable, uncertainty-aware monitoring decisions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class MeasurementQuality(StrEnum):
    CONFIRMED = "CONFIRMED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    STALE = "STALE"


class MonitoringDecision(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class MonitoringObservation:
    """One measurement, kept separate from the derived device decision."""

    source: str
    observed_at: str
    reachable: bool | None
    latency_ms: float | None = None
    packet_loss_percent: float | None = None
    quality: MeasurementQuality = MeasurementQuality.CONFIRMED
    confidence: float = 1.0
    missing_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("measurement source is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.latency_ms is not None and self.latency_ms < 0:
            raise ValueError("latency cannot be negative")
        if self.packet_loss_percent is not None and not 0 <= self.packet_loss_percent <= 100:
            raise ValueError("packet loss must be between 0 and 100")


@dataclass(frozen=True, slots=True)
class MonitoringDecisionResult:
    decision: MonitoringDecision
    reason: str
    confidence: float


@dataclass(frozen=True, slots=True)
class DecisionThresholds:
    warning_latency_ms: float = 250.0
    warning_packet_loss_percent: float = 10.0
    minimum_confidence: float = 0.5

    def __post_init__(self) -> None:
        if self.warning_latency_ms < 0 or self.warning_packet_loss_percent < 0:
            raise ValueError("warning thresholds cannot be negative")
        if not 0 <= self.minimum_confidence <= 1:
            raise ValueError("minimum_confidence must be between 0 and 1")


def classify(
    observations: tuple[MonitoringObservation, ...] | list[MonitoringObservation],
    thresholds: DecisionThresholds = DecisionThresholds(),
) -> MonitoringDecisionResult:
    """Derive a status without treating an unavailable probe as offline."""
    if not observations:
        return MonitoringDecisionResult(
            MonitoringDecision.UNKNOWN,
            "No monitoring observations are available",
            0.0,
        )
    current = observations[-1]
    if current.quality in {MeasurementQuality.FAILED, MeasurementQuality.STALE}:
        return MonitoringDecisionResult(
            MonitoringDecision.UNKNOWN,
            current.missing_reason or f"{current.source} measurement is {current.quality.value.lower()}",
            current.confidence,
        )
    if current.confidence < thresholds.minimum_confidence:
        return MonitoringDecisionResult(
            MonitoringDecision.UNKNOWN,
            "Measurement confidence is below the configured minimum",
            current.confidence,
        )
    if current.reachable is False:
        return MonitoringDecisionResult(
            MonitoringDecision.UNKNOWN,
            f"{current.source} did not confirm reachability",
            current.confidence,
        )
    if current.reachable is None:
        return MonitoringDecisionResult(
            MonitoringDecision.UNKNOWN,
            current.missing_reason or "Reachability is unavailable",
            current.confidence,
        )
    warnings: list[str] = []
    if current.latency_ms is not None and current.latency_ms >= thresholds.warning_latency_ms:
        warnings.append(f"latency {current.latency_ms:.1f} ms exceeds threshold")
    if (
        current.packet_loss_percent is not None
        and current.packet_loss_percent >= thresholds.warning_packet_loss_percent
    ):
        warnings.append(f"packet loss {current.packet_loss_percent:.1f}% exceeds threshold")
    if warnings:
        return MonitoringDecisionResult(
            MonitoringDecision.DEGRADED,
            "; ".join(warnings),
            current.confidence,
        )
    return MonitoringDecisionResult(
        MonitoringDecision.HEALTHY,
        f"{current.source} confirmed reachability within configured thresholds",
        current.confidence,
    )
