"""ECIV correlation, adaptive verification, quarantine, and promotion."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from uuid import uuid4

from .models import (
    ConflictType,
    IdentityConflict,
    IdentityState,
    NetworkObservation,
    VerificationResult,
)
from .scoring import EvidenceWeights, compare_observations
from .state import IdentityStateManager


@dataclass
class _IdentityRecord:
    identity_id: str
    state_manager: IdentityStateManager = field(default_factory=IdentityStateManager)
    confidence: float = 1.0
    observations: list[NetworkObservation] = field(default_factory=list)
    unresolved_observations: list[NetworkObservation] = field(default_factory=list)
    conflicts: list[IdentityConflict] = field(default_factory=list)
    consistent_count: int = 0


class EvidenceCorrelatedIdentityEngine:
    """Maintain identity lineage while isolating unresolved behavior."""

    def __init__(
        self,
        *,
        weights: EvidenceWeights = EvidenceWeights(),
        minimum_consistent_observations: int = 3,
        minimum_promotion_confidence: float = 0.75,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        if minimum_consistent_observations < 1:
            raise ValueError("minimum_consistent_observations must be positive")
        if not 0.0 <= minimum_promotion_confidence <= 1.0:
            raise ValueError("minimum_promotion_confidence must be between 0 and 1")
        self.weights = weights
        self.minimum_consistent_observations = minimum_consistent_observations
        self.minimum_promotion_confidence = minimum_promotion_confidence
        self._records: dict[str, _IdentityRecord] = {}
        self._on_event = on_event

    @staticmethod
    def _identity_key(observation: NetworkObservation) -> str:
        normalized = observation.normalized()
        # Hostname/fingerprint provide continuity when a privacy MAC rotates.
        stable = (
            normalized.hostname
            if normalized.hostname not in {"Unknown", "unknown", ""}
            else normalized.fingerprint
        )
        if not stable:
            stable = normalized.mac if normalized.mac != "UNKNOWN" else normalized.ip
        return stable

    def identity_key(self, observation: NetworkObservation) -> str:
        """Return the normalized correlation key used by this engine."""
        return self._identity_key(observation)

    def _emit(self, event_type: str, record: _IdentityRecord, **evidence: Any) -> None:
        if self._on_event:
            self._on_event(
                event_type,
                {
                    "event_id": str(uuid4()),
                    "device_identity_id": record.identity_id,
                    "event_type": event_type,
                    "severity": "INFO",
                    "previous_state": record.state_manager.state.value,
                    "new_state": record.state_manager.state.value,
                    "confidence": record.confidence,
                    "evidence": evidence,
                },
            )

    def _record_for(self, observation: NetworkObservation) -> _IdentityRecord:
        key = self._identity_key(observation)
        if key not in self._records:
            self._records[key] = _IdentityRecord(identity_id=f"DEV-{uuid4().hex[:12].upper()}")
            self._emit("IDENTITY_CREATED", self._records[key], observation_id=observation.observation_id)
        return self._records[key]

    def observe(self, observation: NetworkObservation) -> _IdentityRecord:
        current = observation.normalized()
        record = self._record_for(current)
        previous = record.observations[-1] if record.observations else None
        if previous is None:
            record.observations.append(current)
            self._emit("IDENTITY_OBSERVATION_ADDED", record, observation_id=current.observation_id)
            return record

        confidence, evidence = compare_observations(previous, current, self.weights)
        record.confidence = confidence
        changed = [
            field
            for field in ("mac", "hostname", "fingerprint")
            if getattr(previous, field) not in (None, "Unknown")
            and getattr(current, field) not in (None, "Unknown")
            and getattr(previous, field) != getattr(current, field)
        ]
        if changed:
            conflict_type = (
                ConflictType.MULTIPLE_ATTRIBUTES_CHANGED if len(changed) > 1
                else ConflictType(f"{changed[0].upper()}_CHANGED")
            )
            conflict = IdentityConflict(
                identity_id=record.identity_id,
                conflict_type=conflict_type,
                observations=(previous.observation_id, current.observation_id),
                severity="HIGH" if "mac" in changed else "MEDIUM",
                uncertainty_score=round(1.0 - confidence, 4),
                reason=", ".join(f"{item} conflict" for item in changed),
            )
            record.conflicts.append(conflict)
            record.unresolved_observations.append(current)
            record.observations.append(current)
            record.state_manager.transition(IdentityState.UNCERTAIN)
            self._emit("IDENTITY_CONFLICT_DETECTED", record, conflict=conflict, evidence=evidence)
            record.state_manager.transition(IdentityState.VERIFYING)
            self._emit("IDENTITY_VERIFICATION_STARTED", record, strategy=self.select_strategy(conflict))
            return record

        record.observations.append(current)
        record.consistent_count += 1
        if record.state_manager.state in {IdentityState.VERIFYING, IdentityState.UNRESOLVED}:
            if (
                record.consistent_count >= self.minimum_consistent_observations
                and confidence >= self.minimum_promotion_confidence
            ):
                record.state_manager.transition(IdentityState.CONFIRMED_CHANGE)
                self._emit("IDENTITY_CONFIRMED_CHANGE", record, evidence=evidence)
                record.state_manager.transition(IdentityState.TRUSTED)
                record.observations.extend(record.unresolved_observations)
                record.unresolved_observations.clear()
                self._emit("IDENTITY_EVIDENCE_PROMOTED", record, evidence=evidence)
            else:
                record.state_manager.transition(IdentityState.UNRESOLVED)
                self._emit("IDENTITY_UNRESOLVED", record, evidence=evidence)
        else:
            self._emit("IDENTITY_OBSERVATION_ADDED", record, observation_id=current.observation_id)
        return record

    @staticmethod
    def select_strategy(conflict: IdentityConflict) -> str:
        return {
            ConflictType.MAC_CHANGED: "fingerprint_service_hostname",
            ConflictType.HOSTNAME_CHANGED: "dns_mdns_netbios",
            ConflictType.FINGERPRINT_CHANGED: "service_behavior",
            ConflictType.BEHAVIOR_CHANGED: "increased_health_sampling",
        }.get(conflict.conflict_type, "multi_signal_verification")

    def verify(self, identity_id: str, result: VerificationResult) -> _IdentityRecord:
        record = next((item for item in self._records.values() if item.identity_id == identity_id), None)
        if record is None:
            raise KeyError(identity_id)
        record.confidence = max(0.0, min(1.0, result.confidence_after))
        self._emit("IDENTITY_VERIFICATION_COMPLETED", record, strategy=result.strategy, evidence=result.evidence)
        if not result.consistent:
            record.state_manager.state = IdentityState.UNRESOLVED
        return record

    def records(self) -> tuple[_IdentityRecord, ...]:
        return tuple(self._records.values())
