import ipaddress
import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch

from main import Device, detect_local_subnet, has_admin_privileges, normalize_mac
from vendor_lookup import lookup_vendor, normalize_mac_prefix
from database_manager import NetworkDatabase
from port_scanner import OpenPort, scan_ports
from notifications import notify_new_device
from backend.services import DashboardService
from backend.services import AlertService
from backend.services import AnalyticsService
from backend.services import AnomalyDetectionService
from backend.notifications import InAppProvider, NotificationDispatcher, NotificationMessage
from backend.monitoring import (
    ContinuousDiscoveryService,
    DeviceRegistry,
    HealthCheckResult,
    HealthMonitor,
    HealthMonitoringService,
    HealthSettings,
)
from backend.scanning import ContinuousPortMonitoringService, PortMonitoringSettings
from backend.websocket import EventHub
from backend.core import RuntimeSettings


class NetworkUtilityTests(unittest.TestCase):
    def test_runtime_settings_validate_ranges_and_ports(self):
        settings = RuntimeSettings(port_list=(22, 443), concurrency=4)
        self.assertEqual(settings.port_list, (22, 443))
        with self.assertRaises(ValueError):
            RuntimeSettings(port_list=(70000,))
        with self.assertRaises(ValueError):
            RuntimeSettings(discovery_interval=0)
    def test_anomaly_assessment_explains_high_risk_signals(self):
        device = Device(ip="192.168.1.24", vendor="Unknown", latency_ms=400)
        assessment = AnomalyDetectionService().assess(
            device,
            open_ports=[{"port": 22}, {"port": 3389}],
            port_events=[{"event_type": "NEW_OPEN_PORT"}] * 3,
            device_events=[
                {"event_type": "DEVICE_DISCOVERED"},
                {"event_type": "DEVICE_OFFLINE"},
                {"event_type": "DEVICE_ONLINE"},
            ],
        )
        self.assertEqual(assessment.score, 100)
        self.assertEqual(assessment.level, "CRITICAL")
        self.assertIn("Unknown vendor", assessment.reasons)
        self.assertIn("New device", assessment.reasons)
        self.assertIn("Unexpected open port(s): 22, 3389", assessment.reasons)
        self.assertIn("Suspicious service/port combination", assessment.reasons)

    def test_anomaly_low_risk_has_no_unfounded_malicious_claim(self):
        assessment = AnomalyDetectionService().assess(
            Device(ip="192.168.1.25", vendor="Known Vendor"),
        )
        self.assertEqual((assessment.score, assessment.level), (0, "LOW"))
        self.assertEqual(assessment.title, "Potentially suspicious activity")
    def test_analytics_queries_are_bounded_and_aggregated(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "analytics.db") as database:
                database.insert_scan_record(0, timestamp="2099-01-01T00:00:00+00:00")
                database.record_health_sample(
                    "192.168.1.90", "ONLINE", 12.0, True, 0,
                    observed_at="2099-01-01T00:01:00+00:00",
                )
                database.record_health_sample(
                    "192.168.1.90", "OFFLINE", None, False, 1,
                    observed_at="2099-01-01T00:02:00+00:00",
                )
                data = database.fetch_history_analytics("2098-12-31T00:00:00+00:00", 60, limit=2)
                self.assertLessEqual(len(data["availability"]), 2)
                self.assertEqual(data["availability"][0]["online"], 1)
                self.assertEqual(data["availability"][0]["offline"], 1)

    def test_analytics_service_rejects_unsupported_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "analytics.db") as database:
                with self.assertRaises(ValueError):
                    AnalyticsService(database).get_history("90d")

    def test_event_hub_serializes_consistent_live_message_envelope(self):
        hub = EventHub()
        messages = []
        unsubscribe = hub.subscribe(messages.append)
        message = hub.publish("DEVICE_ONLINE", {"ip": "192.168.1.2"})
        unsubscribe()
        decoded = json.loads(message)
        self.assertEqual(decoded["event"], "DEVICE_ONLINE")
        self.assertEqual(decoded["data"], {"ip": "192.168.1.2"})
        self.assertIn("timestamp", decoded)
        self.assertEqual(json.loads(messages[0]), decoded)

    def test_detect_local_subnet_uses_connected_interface(self):
        class FakeSocket:
            def connect(self, address):
                self.address = address

            def getsockname(self):
                return ("192.168.50.23", 0)

            def close(self):
                pass

        with patch("main.socket.socket", return_value=FakeSocket()):
            self.assertEqual(detect_local_subnet(), ipaddress.ip_network("192.168.50.0/24"))

    def test_device_row_formats_latency_and_unknown_values(self):
        row = Device(ip="192.168.1.4", status="Online", latency_ms=3.14159, last_seen="now").as_row()
        self.assertEqual(row, ("192.168.1.4", "Unknown", "Unknown", "Unknown", "Online", "3.1 ms", "now"))

    def test_mac_normalization(self):
        self.assertEqual(normalize_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(normalize_mac(""), "Unknown")

    def test_vendor_lookup_normalizes_common_mac_separators(self):
        database = {"AABBCC": "Example Networks"}
        self.assertEqual(normalize_mac_prefix("aa-bb-cc-dd-ee-ff"), "AABBCC")
        self.assertEqual(lookup_vendor("aa:bb:cc:dd:ee:ff", database), "Example Networks")

    def test_vendor_lookup_handles_unknown_and_invalid_macs(self):
        self.assertEqual(lookup_vendor("00:00:00:00:00:00", {}), "Unknown")
        self.assertEqual(lookup_vendor("not-a-mac", {}), "Unknown")

    def test_database_creates_tables_and_upserts_device_history(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "network_logs.db"
            with NetworkDatabase(database_path) as database:
                database.upsert_device("192.168.1.20", "AA:BB:CC:DD:EE:FF", "router", "Example", "first")
                database.upsert_device("192.168.1.20", "AA:BB:CC:DD:EE:FF", "router.local", "Example", "second")
                devices = database.fetch_devices()
                self.assertEqual(len(devices), 1)
                self.assertEqual(devices[0]["first_seen"], "first")
                self.assertEqual(devices[0]["last_seen"], "second")
                self.assertEqual(database_path.exists(), True)

    def test_database_records_and_fetches_scan_history(self):
        class FoundDevice:
            ip = "192.168.1.21"
            mac = "00:11:22:33:44:55"
            hostname = "laptop"
            vendor = "Example"

        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "network_logs.db") as database:
                database.record_scan([FoundDevice()], total_devices_online=1)
                logs = database.fetch_scan_logs()
                self.assertEqual(logs[0]["total_devices_online"], 1)
                self.assertIn("timestamp", logs[0])

    def test_dashboard_service_returns_database_backed_statistics(self):
        class FoundDevice:
            ip = "192.168.1.21"
            mac = "00:11:22:33:44:55"
            hostname = "laptop"
            vendor = "Example"

        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "network_logs.db") as database:
                database.upsert_device("192.168.1.22", hostname="offline-host", seen_at="2024-01-01T00:00:00+00:00")
                database.record_scan([FoundDevice()], total_devices_online=1)
                database.record_port_observations(
                    "192.168.1.21",
                    [OpenPort(443, "HTTPS"), OpenPort(80, "HTTP")],
                )
                stats = DashboardService(database).get_stats()
                self.assertEqual((stats.total_devices, stats.online_devices, stats.offline_devices), (2, 1, 1))
                self.assertEqual(stats.unknown_devices, 0)
                self.assertEqual(stats.open_ports, 2)
                self.assertEqual(stats.active_alerts, 0)
                self.assertEqual(stats.recently_offline[0]["ip"], "192.168.1.22")
                self.assertEqual(len(stats.recent_scans), 1)

    def test_dashboard_service_rejects_invalid_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "network_logs.db") as database:
                with self.assertRaises(ValueError):
                    DashboardService(database).get_stats(recent_limit=0)

    def test_device_registry_classifies_new_and_existing_devices(self):
        registry = DeviceRegistry()
        first = Device(ip="192.168.1.30", mac="AA:BB:CC:DD:EE:FF", status="Online")
        self.assertEqual(registry.apply([first]).new, (first,))
        second = Device(ip="192.168.1.30", mac="AA:BB:CC:DD:EE:FF", status="Online")
        self.assertEqual(registry.apply([second]).existing, (second,))

    def test_device_registry_classifies_disappeared_and_returned_devices(self):
        registry = DeviceRegistry()
        first = Device(ip="192.168.1.31", status="Online")
        registry.apply([first])
        disappeared = registry.apply([]).disappeared
        self.assertEqual(disappeared[0].ip, first.ip)
        self.assertEqual(disappeared[0].status, "Offline")
        returned = Device(ip=first.ip, status="Online")
        self.assertEqual(registry.apply([returned]).returned, (returned,))

    def test_device_registry_deduplicates_duplicate_observations(self):
        registry = DeviceRegistry()
        first = Device(ip="192.168.1.32", hostname="first", status="Online")
        duplicate = Device(ip="192.168.1.32", hostname="last", status="Online")
        transitions = registry.apply([first, duplicate])
        self.assertEqual(len(transitions.new), 1)
        self.assertEqual(registry.devices["192.168.1.32"].hostname, "last")

    def test_continuous_service_runs_a_cycle_and_persists_it(self):
        class FakeScanner:
            def scan(self, subnet, on_progress, on_complete, on_error, on_stopped=None):
                self.subnet = subnet
                on_progress(1, 1)
                on_complete([Device(ip="192.168.1.40", status="Online", latency_ms=2.5)])

            def stop(self):
                return None

        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "network_logs.db") as database:
                service = ContinuousDiscoveryService(
                    FakeScanner(),
                    database,
                    lambda: ipaddress.ip_network("192.168.1.0/30"),
                    interval_seconds=10,
                )
                self.assertTrue(service.run_once())
                self.assertEqual(database.fetch_devices()[0]["ip"], "192.168.1.40")
                self.assertEqual(database.fetch_devices()[0]["latency_ms"], 2.5)
                self.assertTrue(service.run_once())

    def test_health_monitor_requires_consecutive_failures_before_offline(self):
        monitor = HealthMonitor(HealthSettings(failure_threshold=3))
        device = Device(ip="192.168.1.50", status="ONLINE")
        self.assertEqual(monitor.evaluate(device, HealthCheckResult(False, None)), "UNKNOWN")
        self.assertEqual(monitor.evaluate(device, HealthCheckResult(False, None)), "WARNING")
        self.assertEqual(monitor.evaluate(device, HealthCheckResult(False, None)), "OFFLINE")

    def test_health_monitor_marks_high_latency_warning_and_recovers(self):
        monitor = HealthMonitor(HealthSettings(warning_latency_threshold=100))
        device = Device(ip="192.168.1.51", status="UNKNOWN")
        self.assertEqual(monitor.evaluate(device, HealthCheckResult(True, 150)), "WARNING")
        self.assertEqual(monitor.evaluate(device, HealthCheckResult(True, 12)), "ONLINE")

    def test_health_service_persists_health_history(self):
        registry = DeviceRegistry()
        registry.apply([Device(ip="192.168.1.52", status="ONLINE")])
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "health.db") as database:
                service = HealthMonitoringService(
                    registry,
                    database,
                    lambda _ip, _timeout: (True, 4.5),
                    HealthSettings(),
                )
                self.assertTrue(service.run_once())
                history = database.fetch_health_history("192.168.1.52")
                self.assertEqual(history[0]["status"], "ONLINE")
                self.assertEqual(history[0]["latency_ms"], 4.5)

    def test_port_scan_detects_new_and_closed_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "ports.db") as database:
                first = database.record_port_scan("192.168.1.60", [OpenPort(80, "HTTP")])
                second = database.record_port_scan("192.168.1.60", [])
                self.assertEqual(first[0]["event_type"], "NEW_OPEN_PORT")
                self.assertEqual(second[0]["event_type"], "PORT_CLOSED")
                self.assertEqual(database.fetch_port_summary("192.168.1.60"), [])

    def test_alert_lifecycle_deduplicates_and_resolves(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "alerts.db") as database:
                service = AlertService(database)
                first = service.create("DEVICE_OFFLINE", "HIGH", "Device offline", "192.168.1.70")
                duplicate = service.create("DEVICE_OFFLINE", "HIGH", "Still offline", "192.168.1.70")
                self.assertIsNotNone(first)
                self.assertIsNone(duplicate)
                service.acknowledge(first["id"])
                self.assertEqual(service.active()[0]["acknowledged"], 1)
                service.resolve(first["id"])
                self.assertEqual(service.active(), [])
                self.assertEqual(len(service.history()), 1)

    def test_alert_service_rejects_unknown_types_and_severity(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "alerts.db") as database:
                service = AlertService(database)
                with self.assertRaises(ValueError):
                    service.create("NOT_REAL", "HIGH", "bad")
                with self.assertRaises(ValueError):
                    service.create("SCAN_FAILURE", "URGENT", "bad")

    def test_notification_dispatcher_routes_by_severity_and_isolates_failures(self):
        calls = []

        class Provider:
            def __init__(self, name, fail=False):
                self.name = name
                self.fail = fail

            def send(self, notification):
                calls.append((self.name, notification.severity))
                if self.fail:
                    raise RuntimeError("provider unavailable")

        dispatcher = NotificationDispatcher(
            [Provider("dashboard"), Provider("email", fail=True), Provider("webhook")]
        )
        delivered = dispatcher.dispatch(
            NotificationMessage("Critical", "Failure", "CRITICAL", alert_id=1)
        )
        self.assertEqual(delivered, ["dashboard", "webhook"])
        self.assertEqual(
            calls,
            [("dashboard", "CRITICAL"), ("email", "CRITICAL"), ("webhook", "CRITICAL")],
        )

    def test_alert_creation_dispatches_only_for_new_active_alert(self):
        sent = []

        class Provider:
            name = "dashboard"

            def send(self, notification):
                sent.append(notification)

        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "notifications.db") as database:
                dispatcher = NotificationDispatcher([Provider()])
                service = AlertService(database, dispatcher)
                service.create("NEW_DEVICE", "INFO", "New device", "192.168.1.80")
                service.create("NEW_DEVICE", "INFO", "Still new", "192.168.1.80")
                self.assertEqual(len(sent), 1)

    def test_in_app_provider_persists_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "notifications.db") as database:
                InAppProvider(database).send(
                    NotificationMessage("Title", "Message", "MEDIUM", alert_id=4)
                )
                deliveries = database.fetch_notification_deliveries(alert_id=4)
                self.assertEqual(deliveries[0]["channel"], "dashboard")
                self.assertEqual(deliveries[0]["status"], "delivered")

    def test_continuous_port_service_uses_configured_ports_and_persists(self):
        registry = DeviceRegistry()
        registry.apply([Device(ip="192.168.1.61", status="ONLINE")])
        calls = []

        def scanner(ip, **kwargs):
            calls.append((ip, kwargs))
            return [OpenPort(443, "HTTPS")]

        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "ports.db") as database:
                service = ContinuousPortMonitoringService(
                    registry,
                    database,
                    scanner,
                    PortMonitoringSettings(ports=(80, 443), timeout=0.2, max_workers=2),
                )
                results = service.run_once()
                self.assertTrue(results)
                self.assertEqual(calls[0][1]["ports"], (80, 443))
                self.assertEqual(database.fetch_port_summary("192.168.1.61")[0]["port"], 443)

    @patch("port_scanner.socket.create_connection")
    def test_port_scanner_returns_open_ports_and_services(self, create_connection):
        class FakeConnection:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        def connect(address, timeout):
            if address[1] == 443:
                return FakeConnection()
            raise ConnectionRefusedError

        create_connection.side_effect = connect
        self.assertEqual(scan_ports("192.168.1.5", ports=[80, 443]), [OpenPort(443, "HTTPS")])

    def test_port_scanner_validates_arguments(self):
        with self.assertRaises(ValueError):
            scan_ports("192.168.1.5", ports=[0])

    @patch("main.os.geteuid", return_value=0)
    def test_privilege_helper_detects_root(self, _geteuid):
        self.assertTrue(has_admin_privileges())

    @patch("main.os.geteuid", return_value=1000)
    def test_privilege_helper_detects_unprivileged_mode(self, _geteuid):
        self.assertFalse(has_admin_privileges())

    @patch("main.resolve_hostname", return_value="host.local")
    @patch("main.resolve_mac_from_arp", return_value="Unknown")
    @patch("main.NetworkScanner._tcp_probe", return_value=True)
    @patch("main.ping_host", return_value=(False, None))
    def test_layered_scan_uses_tcp_when_ping_is_blocked(
        self, _ping, _tcp_probe, _arp_lookup, _hostname
    ):
        scanner = __import__("main").NetworkScanner(max_workers=2, host_timeout=0.01)
        progress = []
        devices = scanner._layered_scan(ipaddress.ip_network("192.168.1.0/30"), {}, lambda done, total: progress.append((done, total)))
        self.assertEqual(len(devices), 2)
        self.assertEqual({device.status for device in devices}, {"Online"})
        self.assertEqual(progress[-1], (2, 2))

    @patch("notifications.notification")
    def test_new_device_notification_uses_hostname_or_ip(self, notifier):
        self.assertTrue(notify_new_device("192.168.1.30", "printer.local"))
        notifier.notify.assert_called_once()
        self.assertEqual(notifier.notify.call_args.kwargs["message"], "New Device Detected: printer.local")


if __name__ == "__main__":
    unittest.main()
