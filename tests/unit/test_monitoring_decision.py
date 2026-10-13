from __future__ import annotations

import unittest

from src.monitoring import (
    DecisionThresholds,
    MeasurementQuality,
    MonitoringDecision,
    MonitoringObservation,
    classify,
)


class MonitoringDecisionTests(unittest.TestCase):
    def observation(self, **kwargs):
        return MonitoringObservation(
            source="ICMP",
            observed_at="2026-10-13T00:00:00+00:00",
            reachable=True,
            **kwargs,
        )

    def test_successful_measurement_is_healthy(self):
        result = classify([self.observation(latency_ms=12, packet_loss_percent=0)])
        self.assertEqual(result.decision, MonitoringDecision.HEALTHY)

    def test_tcp_success_can_be_degraded_without_icmp_assumption(self):
        result = classify([
            MonitoringObservation(
                source="TCP:443",
                observed_at="2026-10-13T00:00:00+00:00",
                reachable=True,
                latency_ms=400,
            )
        ])
        self.assertEqual(result.decision, MonitoringDecision.DEGRADED)
        self.assertIn("latency", result.reason)

    def test_failed_probe_is_unknown_not_offline(self):
        result = classify([
            MonitoringObservation(
                source="ICMP",
                observed_at="2026-10-13T00:00:00+00:00",
                reachable=False,
                quality=MeasurementQuality.FAILED,
                confidence=0.2,
                missing_reason="timeout",
            )
        ])
        self.assertEqual(result.decision, MonitoringDecision.UNKNOWN)
        self.assertEqual(result.reason, "timeout")

    def test_invalid_measurement_values_are_rejected(self):
        with self.assertRaises(ValueError):
            self.observation(latency_ms=-1)
        with self.assertRaises(ValueError):
            self.observation(confidence=1.1)


if __name__ == "__main__":
    unittest.main()
