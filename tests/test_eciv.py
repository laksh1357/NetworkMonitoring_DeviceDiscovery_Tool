"""Focused tests for the configurable ECIV identity state machine."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.identity import (
    EvidenceCorrelatedIdentityEngine,
    IdentityState,
    IdentityVerificationService,
    NetworkObservation,
)
from backend.identity.models import VerificationResult
from database_manager import NetworkDatabase


class EcivTests(unittest.TestCase):
    def observation(self, mac: str, *, ports: tuple[int, ...] = (22, 443)) -> NetworkObservation:
        return NetworkObservation(
            ip="192.168.1.20",
            mac=mac,
            hostname="laptop.local",
            vendor="Example",
            fingerprint="fingerprint-a",
            open_ports=ports,
            latency_ms=5,
            source="ARP",
        )

    def test_mac_conflict_enters_verifying_and_quarantines_behavior(self):
        engine = EvidenceCorrelatedIdentityEngine()
        first = engine.observe(self.observation("AA:BB:CC:00:00:01"))
        second = engine.observe(self.observation("DD:EE:FF:00:00:02", ports=(22, 443, 8080)))

        self.assertEqual(first.identity_id, second.identity_id)
        self.assertEqual(second.state_manager.state, IdentityState.VERIFYING)
        self.assertEqual(len(second.unresolved_observations), 1)
        self.assertEqual(second.conflicts[0].conflict_type.value, "MAC_CHANGED")

    def test_consistent_evidence_promotes_after_configured_threshold(self):
        engine = EvidenceCorrelatedIdentityEngine(minimum_consistent_observations=1)
        engine.observe(self.observation("AA:BB:CC:00:00:01"))
        record = engine.observe(self.observation("DD:EE:FF:00:00:02"))
        self.assertEqual(record.state_manager.state, IdentityState.VERIFYING)
        engine.verify(
            record.identity_id,
            VerificationResult("fingerprint_service_hostname", 0.4, 0.9, True, {"match": True}),
        )
        promoted = engine.observe(self.observation("DD:EE:FF:00:00:02"))
        self.assertEqual(promoted.state_manager.state, IdentityState.TRUSTED)
        self.assertEqual(promoted.unresolved_observations, [])

    def test_identity_observations_are_persisted_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "eciv.db") as database:
                database.save_identity("DEV-1", "laptop.local", "UNCERTAIN", 0.61)
                observation = self.observation("AA:BB:CC:00:00:01")
                database.save_identity_observation(
                    "DEV-1",
                    {
                        "observation_id": observation.observation_id,
                        "observed_at": observation.observed_at,
                        "ip": observation.ip,
                        "mac": observation.mac,
                        "hostname": observation.hostname,
                        "vendor": observation.vendor,
                        "fingerprint": observation.fingerprint,
                        "open_ports": list(observation.open_ports),
                        "latency_ms": observation.latency_ms,
                        "source": observation.source,
                    },
                )
                self.assertEqual(len(database.fetch_identity_observations("DEV-1")), 1)

    def test_service_persists_identity_and_conflict_history(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "service.db") as database:
                service = IdentityVerificationService(database)
                first = self.observation("AA:BB:CC:00:00:01")
                second = self.observation("DD:EE:FF:00:00:02")
                identity_id = service.process(first)
                self.assertEqual(service.process(second), identity_id)
                snapshot = service.snapshot(identity_id)
                self.assertIsNotNone(snapshot)
                self.assertEqual(len(snapshot["observations"]), 2)
                self.assertEqual(len(snapshot["conflicts"]), 1)


if __name__ == "__main__":
    unittest.main()
