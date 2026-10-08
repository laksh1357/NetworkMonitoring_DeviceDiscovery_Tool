"""Configurable prototype evidence scoring for ECIV."""

from __future__ import annotations

from dataclasses import dataclass, fields

from .models import NetworkObservation


@dataclass(frozen=True, slots=True)
class EvidenceWeights:
    """Prototype weights, intentionally configurable and not scientifically validated."""

    mac: float = 0.25
    hostname: float = 0.10
    vendor: float = 0.10
    fingerprint: float = 0.25
    ports: float = 0.10
    behavior: float = 0.10
    source: float = 0.10


def _same(left: str | None, right: str | None) -> float:
    if not left or not right or left in {"Unknown", "unknown"} or right in {"Unknown", "unknown"}:
        return 0.0
    return 1.0 if left.casefold() == right.casefold() else 0.0


def compare_observations(
    previous: NetworkObservation,
    current: NetworkObservation,
    weights: EvidenceWeights = EvidenceWeights(),
) -> tuple[float, dict[str, float]]:
    """Return normalized confidence and the individual evidence contributions."""
    contributions = {
        "mac": _same(previous.mac, current.mac),
        "hostname": _same(previous.hostname, current.hostname),
        "vendor": _same(previous.vendor, current.vendor),
        "fingerprint": _same(previous.fingerprint, current.fingerprint),
        "ports": 1.0 if set(previous.open_ports) == set(current.open_ports) else 0.0,
        "behavior": (
            1.0
            if previous.latency_ms is not None
            and current.latency_ms is not None
            and abs(previous.latency_ms - current.latency_ms) <= max(previous.latency_ms, 1.0) * 0.5
            else 0.0
        ),
        "source": _same(previous.source, current.source),
    }
    weighted = sum(getattr(weights, key) * value for key, value in contributions.items())
    total = sum(float(getattr(weights, field.name)) for field in fields(weights))
    return (weighted / total if total else 0.0), contributions
