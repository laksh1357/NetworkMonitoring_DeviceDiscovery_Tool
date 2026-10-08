"""Persistence-aware ECIV orchestration service."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from src.core.database import NetworkDatabase

from .engine import EvidenceCorrelatedIdentityEngine
from .models import NetworkObservation


class IdentityVerificationService:
    """Bridge normalized network observations into ECIV and SQLite."""

    def __init__(
        self,
        database: NetworkDatabase,
        engine: EvidenceCorrelatedIdentityEngine | None = None,
    ) -> None:
        self.database = database
        self.engine = engine or EvidenceCorrelatedIdentityEngine()

    def process(self, observation: NetworkObservation) -> str:
        record = self.engine.observe(observation)
        normalized = observation.normalized()
        self.database.save_identity(
            record.identity_id,
            self.engine.identity_key(normalized),
            record.state_manager.state.value,
            record.confidence,
        )
        self.database.save_identity_observation(
            record.identity_id,
            {
                **asdict(normalized),
                "raw_evidence": normalized.raw_evidence,
            },
        )
        for conflict in record.conflicts:
            self.database.save_identity_conflict(asdict(conflict))
        return record.identity_id

    def snapshot(self, identity_id: str) -> dict[str, Any] | None:
        identity = self.database.fetch_identity(identity_id)
        if identity is None:
            return None
        identity["observations"] = self.database.fetch_identity_observations(identity_id)
        identity["conflicts"] = self.database.fetch_identity_conflicts(identity_id)
        return identity
