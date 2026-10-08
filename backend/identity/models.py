"""Typed ECIV observations, conflicts, and state values."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


class IdentityState(StrEnum):
    TRUSTED = "TRUSTED"
    UNCERTAIN = "UNCERTAIN"
    VERIFYING = "VERIFYING"
    CONFIRMED_CHANGE = "CONFIRMED_CHANGE"
    UNRESOLVED = "UNRESOLVED"
    QUARANTINED = "QUARANTINED"


class ConflictType(StrEnum):
    MAC_CHANGED = "MAC_CHANGED"
    HOSTNAME_CHANGED = "HOSTNAME_CHANGED"
    FINGERPRINT_CHANGED = "FINGERPRINT_CHANGED"
    BEHAVIOR_CHANGED = "BEHAVIOR_CHANGED"
    MULTIPLE_ATTRIBUTES_CHANGED = "MULTIPLE_ATTRIBUTES_CHANGED"


@dataclass(frozen=True, slots=True)
class NetworkObservation:
    """An immutable observation; historical evidence is never overwritten."""

    ip: str
    mac: str = "Unknown"
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    device_type: str = "Unknown"
    open_ports: tuple[int, ...] = ()
    latency_ms: float | None = None
    packet_loss: float | None = None
    source: str = "unknown"
    interface: str = "auto"
    fingerprint: str | None = None
    protocol_observations: dict[str, Any] = field(default_factory=dict)
    raw_evidence: dict[str, Any] = field(default_factory=dict)
    observation_id: str = field(default_factory=lambda: str(uuid4()))
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def normalized(self) -> "NetworkObservation":
        return NetworkObservation(
            observation_id=self.observation_id,
            observed_at=self.observed_at,
            ip=self.ip.strip(),
            mac=self.mac.strip().upper() if self.mac else "Unknown",
            hostname=self.hostname.strip().lower() if self.hostname else "Unknown",
            vendor=self.vendor.strip() if self.vendor else "Unknown",
            device_type=self.device_type.strip() if self.device_type else "Unknown",
            open_ports=tuple(sorted({int(port) for port in self.open_ports if 1 <= int(port) <= 65535})),
            latency_ms=self.latency_ms,
            packet_loss=self.packet_loss,
            source=self.source.strip() or "unknown",
            interface=self.interface.strip() or "auto",
            fingerprint=self.fingerprint.strip() if self.fingerprint else None,
            protocol_observations=dict(self.protocol_observations),
            raw_evidence=dict(self.raw_evidence),
        )


@dataclass(frozen=True, slots=True)
class IdentityConflict:
    identity_id: str
    conflict_type: ConflictType
    observations: tuple[str, ...]
    severity: str
    uncertainty_score: float
    reason: str
    conflict_id: str = field(default_factory=lambda: str(uuid4()))
    status: str = "OPEN"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )


@dataclass(frozen=True, slots=True)
class VerificationResult:
    strategy: str
    confidence_before: float
    confidence_after: float
    consistent: bool
    evidence: dict[str, Any]

