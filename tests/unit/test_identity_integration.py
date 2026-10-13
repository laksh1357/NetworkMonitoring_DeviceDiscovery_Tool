from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.core.database import NetworkDatabase
from src.identity import IdentityVerificationService, NetworkObservation


class IdentityIntegrationTests(unittest.TestCase):
    def test_observation_is_persisted_once_and_replayed_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "eciv.db") as database:
                service = IdentityVerificationService(database)
                observation = NetworkObservation(
                    ip="192.168.1.10",
                    mac="AA:BB:CC:DD:EE:FF",
                    hostname="host.local",
                    vendor="Example",
                    source="ARP",
                    raw_evidence={"collector": "test"},
                    observation_id="obs-1",
                )
                first = service.process(observation)
                second = service.process(observation)

                self.assertEqual(first, second)
                self.assertEqual(len(database.fetch_identity_observations(first)), 1)

    def test_conflicting_observation_is_retained_as_identity_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "eciv.db") as database:
                service = IdentityVerificationService(database)
                first = service.process(
                    NetworkObservation(
                        ip="192.168.1.10",
                        mac="AA:BB:CC:DD:EE:FF",
                        hostname="host.local",
                        source="ARP",
                        observation_id="obs-1",
                    )
                )
                service.process(
                    NetworkObservation(
                        ip="192.168.1.10",
                        mac="11:22:33:44:55:66",
                        hostname="host.local",
                        source="ARP",
                        observation_id="obs-2",
                    )
                )
                identity = database.fetch_identity(first)
                self.assertEqual(identity["current_state"], "VERIFYING")
                self.assertEqual(len(database.fetch_identity_conflicts(first)), 1)


if __name__ == "__main__":
    unittest.main()
