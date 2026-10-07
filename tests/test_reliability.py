"""Isolation and failure-path tests for monitoring reliability."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.core import RuntimeSettings
from backend.api.server import HealthHandler, HealthServer
from backend.monitoring import ContinuousDiscoveryService, DeviceRegistry, HealthMonitor, HealthSettings
from backend.models import Device
from backend.notifications import EmailProvider, NotificationDispatcher, NotificationMessage, WebhookProvider
from backend.scanning import ContinuousPortMonitoringService, PortMonitoringSettings
from backend.services import AlertService, AnalyticsService
from backend.websocket import EventHub, WebSocketServer
from database_manager import NetworkDatabase
from port_scanner import OpenPort, scan_ports


class ReliabilityTests(unittest.TestCase):
    def test_health_and_readiness_endpoints_use_local_temporary_database(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "ready.db"
            with NetworkDatabase(database_path):
                server = HealthServer(host="127.0.0.1", port=0, database_path=database_path)
                thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
                thread.start()
                import urllib.request

                port = server.server.server_address[1]
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health") as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read())["status"], "ok")
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/ready") as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read())["status"], "ready")
                server.server.shutdown()
                thread.join(timeout=2)
    def test_discovery_failure_is_reported_without_network_access(self):
        errors: list[str] = []

        class FailingScanner:
            def scan(self, _subnet, _progress, _complete, on_error, _stopped=None):
                on_error("permission denied")

        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "reliability.db") as database:
                service = ContinuousDiscoveryService(
                    FailingScanner(),
                    database,
                    lambda: ipaddress.ip_network("192.168.1.0/30"),
                    on_error=errors.append,
                )
                self.assertFalse(service.run_once())
        self.assertEqual(errors, ["permission denied"])

    def test_discovery_persists_lifecycle_events_without_duplicates(self):
        class Scanner:
            def __init__(self):
                self.devices = [[Device("192.168.1.10", status="ONLINE")], []]

            def scan(self, _subnet, _progress, on_complete, _error, _stopped=None):
                on_complete(self.devices.pop(0))

        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "lifecycle.db") as database:
                service = ContinuousDiscoveryService(
                    Scanner(), database, lambda: ipaddress.ip_network("192.168.1.0/30")
                )
                self.assertTrue(service.run_once())
                self.assertTrue(service.run_once())
                events = database.fetch_device_events("192.168.1.10")
                self.assertEqual([event["event_type"] for event in events], ["DEVICE_OFFLINE", "DEVICE_DISCOVERED"])
                self.assertEqual(len(database.fetch_devices()), 1)

    def test_health_monitor_threshold_and_recovery(self):
        monitor = HealthMonitor(HealthSettings(failure_threshold=2, warning_latency_threshold=100))
        device = Device("192.168.1.11")
        self.assertEqual(monitor.evaluate(device, type("Result", (), {"reachable": False, "latency_ms": None})()), "UNKNOWN")
        self.assertEqual(monitor.evaluate(device, type("Result", (), {"reachable": False, "latency_ms": None})()), "OFFLINE")
        self.assertEqual(monitor.evaluate(device, type("Result", (), {"reachable": True, "latency_ms": 10})()), "ONLINE")
        self.assertEqual(monitor.failures[device.ip], 0)

    def test_port_monitor_isolates_scanner_errors(self):
        errors: list[str] = []
        registry = DeviceRegistry()
        registry.apply([Device("192.168.1.12", status="ONLINE")])

        def failing_scanner(_ip, **_kwargs):
            raise TimeoutError("port timeout")

        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "ports.db") as database:
                service = ContinuousPortMonitoringService(
                    registry, database, failing_scanner,
                    PortMonitoringSettings(ports=(22,)), on_error=errors.append,
                )
                self.assertTrue(service.run_once())
        self.assertEqual(errors, ["192.168.1.12: port timeout"])

    @patch("port_scanner.socket.create_connection")
    def test_port_scanner_handles_timeout_as_closed(self, create_connection):
        create_connection.side_effect = TimeoutError("timeout")
        self.assertEqual(scan_ports("192.168.1.13", ports=[22], timeout=0.01), [])

    @patch("backend.notifications.providers.smtplib.SMTP")
    def test_email_provider_uses_environment_without_exposing_password(self, smtp_class):
        smtp = smtp_class.return_value.__enter__.return_value
        provider = EmailProvider(
            {
                "NOTIFICATION_EMAIL_ENABLED": "true",
                "SMTP_HOST": "smtp.test",
                "SMTP_PORT": "587",
                "SMTP_USERNAME": "user",
                "SMTP_PASSWORD": "secret",
                "NOTIFICATION_EMAIL_TO": "ops@test",
            }
        )
        provider.send(NotificationMessage("Alert", "Message", "HIGH"))
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("user", "secret")
        sent = smtp.send_message.call_args.args[0]
        self.assertNotIn("secret", sent.as_string())

    @patch("backend.notifications.providers.urllib.request.urlopen")
    def test_webhook_provider_sends_valid_json_payload(self, urlopen):
        provider = WebhookProvider({"WEBHOOK_URL": "https://hooks.test/network"})
        provider.send(NotificationMessage("Alert", "Message", "CRITICAL", alert_id=7))
        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["alert_id"], 7)
        self.assertEqual(request.full_url, "https://hooks.test/network")

    def test_notification_dispatcher_skips_missing_optional_provider(self):
        provider = MagicMock()
        provider.name = "dashboard"
        dispatcher = NotificationDispatcher([provider])
        self.assertEqual(dispatcher.dispatch(NotificationMessage("x", "y", "CRITICAL")), ["dashboard"])
        provider.send.assert_called_once()

    def test_alert_event_callback_runs_for_create_and_resolve(self):
        events: list[tuple[str, dict]] = []
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "alerts.db") as database:
                service = AlertService(database, on_event=lambda name, data: events.append((name, data)))
                alert = service.create("NEW_DEVICE", "INFO", "New device", "192.168.1.14")
                service.resolve(alert["id"])
        self.assertEqual([event[0] for event in events], ["ALERT_CREATED", "ALERT_RESOLVED"])

    def test_websocket_event_hub_removes_failed_subscriber(self):
        hub = EventHub()
        received: list[str] = []

        def broken(_message):
            raise ConnectionError("closed")

        hub.subscribe(broken)
        hub.subscribe(received.append)
        hub.publish("DEVICE_UPDATED", {"ip": "192.168.1.15"})
        hub.publish("DEVICE_UPDATED", {"ip": "192.168.1.15"})
        self.assertEqual(len(received), 2)

    def test_websocket_server_validates_bounds_without_starting_network(self):
        with self.assertRaises(ValueError):
            WebSocketServer(EventHub(), port=0)
        with self.assertRaises(ValueError):
            WebSocketServer(EventHub(), ping_timeout=0)

    def test_analytics_time_ranges_are_whitelisted(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "analytics.db") as database:
                service = AnalyticsService(database)
                for name in ("1h", "6h", "24h", "7d", "30d"):
                    result = service.get_history(name)
                    self.assertEqual(set(result), {"devices", "availability", "alerts", "ports", "device_events", "uptime"})
                with self.assertRaises(ValueError):
                    service.get_history("1 year")

    def test_runtime_settings_rejects_invalid_configuration(self):
        for kwargs in (
            {"timeout": 0},
            {"concurrency": 0},
            {"offline_threshold": 0},
            {"latency_threshold": -1},
            {"port_list": (65536,)},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    RuntimeSettings(**kwargs)

    def test_database_health_history_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "health.db") as database:
                for index in range(5):
                    database.record_health_sample("192.168.1.16", "ONLINE", 1.0, True, 0, f"2026-01-01T00:0{index}:00+00:00")
                self.assertEqual(len(database.fetch_health_history("192.168.1.16", limit=2)), 2)


if __name__ == "__main__":
    unittest.main()
